// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ISafePolicy, PolicyOperation, AccessSelectorLib } from "./ISafePolicy.sol";

/**
 * @title ERC20ApproveCapPolicy
 * @notice Safe Policy Engine policy for `token.approve(spender, amount)`: the spender must be on the
 *         Safe's list for that token, and the amount must not exceed that spender's cap.
 *
 * Upstream `ERC20ApprovePolicy` checks the spender only, and lets anyone be approved for zero. This
 * policy is stricter on both counts: every approval, zero included, must name a listed spender, and
 * the amount is capped, so the floor itself bounds an allowance even if the module that asked for it
 * is compromised. No ETH value is accepted.
 *
 * Configure it on `(token, approve, CALL)` with `abi.encode(SpenderCap[])`. Each entry sets one
 * spender's cap; `allowed = false` removes the spender. Stateless apart from that list.
 */
contract ERC20ApproveCapPolicy is ISafePolicy {
    using AccessSelectorLib for uint256;

    bytes4 internal constant APPROVE = bytes4(keccak256("approve(address,uint256)"));

    struct SpenderCap {
        address spender;
        bool allowed;
        uint248 maxAmount;
    }

    struct Cap {
        bool allowed;
        uint248 maxAmount;
    }

    mapping(
        address guard => mapping(address safe => mapping(address token => mapping(address spender => Cap)))
    ) private $caps;

    error InvalidApproval();
    error SpenderNotAllowed(address spender);
    error AmountAboveCap(uint256 amount, uint256 maxAmount);

    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        PolicyOperation operation,
        address,
        bytes calldata,
        uint256
    ) external view returns (bytes4) {
        require(
            operation == PolicyOperation.CALL && value == 0 && data.length == 68 && bytes4(data) == APPROVE,
            InvalidApproval()
        );
        (address spender, uint256 amount) = abi.decode(data[4:], (address, uint256));
        Cap memory cap = $caps[msg.sender][safe][to][spender];
        require(cap.allowed, SpenderNotAllowed(spender));
        require(amount <= cap.maxAmount, AmountAboveCap(amount, cap.maxAmount));
        return ISafePolicy.checkTransaction.selector;
    }

    /// @dev Namespaced by `msg.sender` (the guard), like every upstream policy.
    function configure(address safe, uint256 access, bytes memory data) external returns (bool) {
        if (access.selector() != APPROVE || access.operation() != PolicyOperation.CALL) return false;
        address token = access.target();
        SpenderCap[] memory caps = abi.decode(data, (SpenderCap[]));
        for (uint256 i; i < caps.length; i++) {
            $caps[msg.sender][safe][token][caps[i].spender] = Cap(caps[i].allowed, caps[i].maxAmount);
        }
        return true;
    }

    function capOf(address guard, address safe, address token, address spender)
        external
        view
        returns (bool allowed, uint256 maxAmount)
    {
        Cap memory cap = $caps[guard][safe][token][spender];
        return (cap.allowed, cap.maxAmount);
    }
}
