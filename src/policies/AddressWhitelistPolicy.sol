// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ConfigId } from "../interfaces/ISessionPolicy.sol";
import { SessionPolicyBase } from "./SessionPolicyBase.sol";
import { TransferLib } from "../libraries/TransferLib.sol";

/**
 * @title AddressWhitelistPolicy (Control 1)
 * @notice Allows an execution only if it is a recognised asset transfer whose *beneficiary* is on
 *         the session's whitelist.
 *
 *  - Native transfer `(to, value, "")`          -> beneficiary = `to`
 *  - ERC-20 `token.transfer(to, amount)`         -> beneficiary = `to` (NOT the token contract)
 *  - Anything else (approve, transferFrom, router calls, multicalls, trailing calldata ...) -> FAIL
 *
 * Because the only accepted shapes are direct transfers, an intermediate contract (router,
 * forwarder, multicall) can never be used to route funds to a non-whitelisted address.
 *
 * initData: `abi.encode(address[] recipients)`. Re-initialising replaces the whole list.
 */
contract AddressWhitelistPolicy is SessionPolicyBase {
    error InvalidRecipient(address recipient);
    error EmptyWhitelist();

    // allowed[configId][multiplexer][epoch][beneficiary][account]
    mapping(
        ConfigId => mapping(address => mapping(uint256 => mapping(address => mapping(address => bool))))
    ) internal $allowed;

    function isWhitelisted(ConfigId id, address multiplexer, address account, address beneficiary)
        external
        view
        returns (bool)
    {
        return $allowed[id][multiplexer][$epoch[id][multiplexer][account]][beneficiary][account];
    }

    function _configure(
        ConfigId id,
        address multiplexer,
        address account,
        uint256 epoch,
        bytes calldata initData
    ) internal override {
        address[] memory recipients = abi.decode(initData, (address[]));
        if (recipients.length == 0) revert EmptyWhitelist();
        for (uint256 i; i < recipients.length; i++) {
            address r = recipients[i];
            // The account itself is never a meaningful beneficiary and address(0) is a burn/typo.
            if (r == address(0) || r == account) revert InvalidRecipient(r);
            $allowed[id][multiplexer][epoch][r][account] = true;
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
        TransferLib.Transfer memory t = TransferLib.decode(target, value, data);
        if (t.kind == TransferLib.Kind.UNSUPPORTED) return false;
        return $allowed[id][multiplexer][epoch][t.beneficiary][account];
    }
}
