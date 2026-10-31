// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ConfigId } from "../interfaces/ISessionPolicy.sol";
import { SessionPolicyBase } from "./SessionPolicyBase.sol";

/**
 * @title FunctionWhitelistPolicy (Control 3)
 * @notice Restricts *which operations* a session may perform, independently of amounts and
 *         beneficiaries:
 *          - plain native transfers (empty calldata) only if `allowNativeTransfers`
 *          - contract calls only for whitelisted `(target, selector)` pairs and only with value == 0
 *
 * Hard rules that configuration cannot override:
 *  - the account itself is never a valid target (no Safe self-calls: owners, threshold, modules,
 *    guard, fallback handler, Safe7579 module management ...)
 *  - the multiplexer (SmartSession) is never a valid target (no session self-management)
 *  - allowance-granting selectors (approve, increaseAllowance, setApprovalForAll, permit) can
 *    never be whitelisted
 *  - calldata of 1..3 bytes (no selector, but would hit the target's fallback) is rejected
 *
 * A whitelisted selector is NOT a statement that every call with that selector is safe: it only
 * says the operation type is permitted. Arguments must be constrained by other policies (here:
 * AddressWhitelistPolicy for beneficiaries and SpendingLimitPolicy for amounts).
 *
 * initData: `abi.encode(bool allowNativeTransfers, Permission[] permissions)`.
 */
contract FunctionWhitelistPolicy is SessionPolicyBase {
    struct Permission {
        address target;
        bytes4 selector;
    }

    error ForbiddenTarget(address target);
    error ForbiddenSelector(bytes4 selector);

    // allowed[configId][multiplexer][epoch][target][selector][account]
    mapping(
        ConfigId
            => mapping(
            address => mapping(uint256 => mapping(address => mapping(bytes4 => mapping(address => bool))))
        )
    ) internal $allowed;
    // native[configId][multiplexer][epoch][account]
    mapping(ConfigId => mapping(address => mapping(uint256 => mapping(address => bool)))) internal $native;

    function isAllowed(ConfigId id, address multiplexer, address account, address target, bytes4 selector)
        external
        view
        returns (bool)
    {
        return $allowed[id][multiplexer][$epoch[id][multiplexer][account]][target][selector][account];
    }

    function _configure(
        ConfigId id,
        address multiplexer,
        address account,
        uint256 epoch,
        bytes calldata initData
    ) internal override {
        (bool allowNative, Permission[] memory perms) = abi.decode(initData, (bool, Permission[]));
        $native[id][multiplexer][epoch][account] = allowNative;
        for (uint256 i; i < perms.length; i++) {
            Permission memory p = perms[i];
            if (p.target == address(0) || p.target == account || p.target == multiplexer) {
                revert ForbiddenTarget(p.target);
            }
            if (_isForbiddenSelector(p.selector)) revert ForbiddenSelector(p.selector);
            $allowed[id][multiplexer][epoch][p.target][p.selector][account] = true;
        }
    }

    function _check(
        ConfigId id,
        address multiplexer,
        address account,
        uint256 epoch,
        address target,
        uint256 value,
        bytes calldata data
    ) internal view override returns (bool) {
        if (target == account || target == multiplexer) return false;
        if (data.length == 0) return $native[id][multiplexer][epoch][account];
        if (data.length < 4 || value != 0) return false;
        return $allowed[id][multiplexer][epoch][target][bytes4(data[0:4])][account];
    }

    function _isForbiddenSelector(bytes4 s) internal pure returns (bool) {
        return s == 0x095ea7b3 // approve(address,uint256)
            || s == 0x39509351 // increaseAllowance(address,uint256)
            || s == 0xa22cb465 // setApprovalForAll(address,bool)
            || s == 0xd505accf; // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
    }
}
