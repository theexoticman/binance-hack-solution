// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC165 } from "forge-std/interfaces/IERC165.sol";

/**
 * @title ISessionPolicy - MIT, ABI-identical declarations of the SmartSessions policy interfaces
 * @notice SmartSession calls policies purely through their ABI. These declarations reproduce the
 *         SmartSessions `IPolicy` / `IActionPolicy` / `IUserOpPolicy` ABIs exactly (same selectors,
 *         same ERC-165 interface ids, same error and event signatures; `ConfigId` is a `bytes32`
 *         value type), so this repository's policies do not compile any copyleft source.
 *         test/LicenseIsolation.t.sol asserts the interface ids match the upstream ones.
 *
 * Rules every policy in this repository follows (enforced by `SessionPolicyBase` where possible):
 *  1. Namespace ALL state by `(configId, multiplexer = msg.sender, account)`. Anyone can call a
 *     policy directly; namespacing guarantees they can only write to their own slot.
 *  2. Fail closed: uninitialised config, unknown calldata shapes and unknown assets MUST fail.
 *  3. Never return anything other than VALIDATION_SUCCESS / VALIDATION_FAILED (no packed time
 *     ranges, no aggregator). SmartSession rejects other values anyway.
 *  4. Policies hold no authority. They are called with CALL (never DELEGATECALL) from SmartSession
 *     and cannot execute on the Safe, so a policy can only *deny*, never *grant*.
 *  5. ERC-4337 / ERC-7562 storage rules: the account must be the innermost mapping key.
 */
type ConfigId is bytes32;

uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;

/// @dev ERC-4337 v0.7 PackedUserOperation (field order and types fixed by the standard).
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

interface IPolicy is IERC165 {
    event PolicySet(ConfigId id, address multiplexer, address account);

    error PolicyNotInitialized(ConfigId id, address multiplexer, address account);

    /// @dev Called by SmartSession when the account enables or re-configures a policy. MUST overwrite.
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external;
}

interface IActionPolicy is IPolicy {
    /// @dev Called during ERC-4337 validation once per execution (every element of a batch).
    function checkAction(ConfigId id, address account, address target, uint256 value, bytes calldata data)
        external
        returns (uint256);
}

interface IUserOpPolicy is IPolicy {
    /// @dev Called during ERC-4337 validation once per user operation.
    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata userOp) external returns (uint256);
}
