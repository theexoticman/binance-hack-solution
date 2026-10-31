// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC165 } from "forge-std/interfaces/IERC165.sol";
import {
    IPolicy,
    IActionPolicy,
    ConfigId,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "../interfaces/ISessionPolicy.sol";

/**
 * @title SessionPolicyBase
 * @notice Minimal base for SmartSessions action policies. Extend it and implement `_configure`
 *         and `_check`; see docs/ADDING_POLICIES.md.
 *
 * What the base guarantees:
 *  - State is namespaced by `(configId, multiplexer = msg.sender, account)`.
 *  - Every (re)configuration bumps an `epoch`. Derived policies key their config by epoch, so a
 *    re-configuration atomically replaces the previous config (removed entries really disappear).
 *  - `checkAction` reverts with `PolicyNotInitialized` if the policy was never configured for this
 *    namespace, which SmartSession surfaces as a validation failure (fail-closed).
 */
abstract contract SessionPolicyBase is IActionPolicy {
    // epoch[configId][multiplexer][account] - 0 means "never configured".
    mapping(ConfigId => mapping(address => mapping(address => uint256))) internal $epoch;

    /// @inheritdoc IPolicy
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        uint256 epoch = ++$epoch[configId][msg.sender][account];
        _configure(configId, msg.sender, account, epoch, initData);
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    /// @inheritdoc IActionPolicy
    function checkAction(ConfigId id, address account, address target, uint256 value, bytes calldata data)
        external
        returns (uint256)
    {
        uint256 epoch = $epoch[id][msg.sender][account];
        if (epoch == 0) revert PolicyNotInitialized(id, msg.sender, account);
        return
            _check(id, msg.sender, account, epoch, target, value, data)
                ? VALIDATION_SUCCESS
                : VALIDATION_FAILED;
    }

    function isInitialized(ConfigId id, address multiplexer, address account) external view returns (bool) {
        return $epoch[id][multiplexer][account] != 0;
    }

    function supportsInterface(bytes4 interfaceId) external pure virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IPolicy).interfaceId
            || interfaceId == type(IActionPolicy).interfaceId;
    }

    /// @dev Store the configuration for `epoch`. MUST revert on malformed input.
    function _configure(
        ConfigId id,
        address multiplexer,
        address account,
        uint256 epoch,
        bytes calldata initData
    ) internal virtual;

    /// @dev Return true to allow the execution. May mutate state (e.g. spending counters).
    function _check(
        ConfigId id,
        address multiplexer,
        address account,
        uint256 epoch,
        address target,
        uint256 value,
        bytes calldata data
    ) internal virtual returns (bool);
}
