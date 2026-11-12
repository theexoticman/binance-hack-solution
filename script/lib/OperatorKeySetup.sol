// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ConditionFlat, ParameterType, Operator, ExecutionOptions } from "zodiac-roles/Types.sol";
import { Session } from "smartsessions/DataTypes.sol";
import { ISessionValidator } from "smartsessions/interfaces/ISessionValidator.sol";
import { SessionSetup } from "./SessionSetup.sol";
import { FunctionWhitelistPolicy } from "../../src/policies/FunctionWhitelistPolicy.sol";
import { SpendingLimitPolicy } from "../../src/policies/SpendingLimitPolicy.sol";

/// @dev ABI of `SafePolicyGuard.Configuration` (safe-research/policy-engine).
struct PolicyConfig {
    address target;
    bytes4 selector;
    uint8 operation; // 0 CALL, 1 DELEGATECALL
    address policy;
    bytes data;
}

/// @dev Upstream `ERC20TransferPolicy.RecipientData` (Permission: 0 NONE, 1 ONCE, 2 ALWAYS).
struct RecipientData {
    address recipient;
    uint8 permission;
}

/**
 * @notice Calldata builders for the two restricted operator-key architectures, shared by
 *         script/DeployOperatorKeys.s.sol and test/operator-keys. Nothing here is deployed; it shows,
 *         in one place, exactly what the Safe owners sign. (Smart Sessions' own session layout is in
 *         SessionSetup.sol and is reused unchanged.)
 */
library OperatorKeySetup {
    // Selectors, derived from signatures (no Safe/Roles implementation imports needed here).
    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 internal constant MULTISEND = bytes4(keccak256("multiSend(bytes)"));
    bytes4 internal constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));
    bytes4 internal constant DISABLE_MODULE = bytes4(keccak256("disableModule(address,address)"));
    bytes4 internal constant ASSIGN_ROLES = bytes4(keccak256("assignRoles(address,bytes32[],bool[])"));

    struct Common {
        address safe;
        address token; // the one operational asset
        address[] recipients; // its allowed recipients
        address multiSend; // MultiSendCallOnly v1.5.0
        address erc20TransferPolicy;
        address multiSendPolicy;
        address increasedThresholdPolicy;
        address ownerOnlyPolicy;
    }

    /**
     * Policy Engine entries shared by both architectures (default-deny everything else):
     *   token.transfer            CALL          ERC20TransferPolicy   recipients only
     *   MultiSendCallOnly         DELEGATECALL  MultiSendPolicy       each sub-transaction re-checked
     *   Safe.swapOwner            CALL          IncreasedThresholdPolicy (all owners but one, >= threshold + 1)
     *   Safe.disableModule        CALL          OwnerOnlyPolicy       emergency kill switch
     */
    function commonPolicies(Common memory c) internal pure returns (PolicyConfig[] memory p) {
        RecipientData[] memory r = new RecipientData[](c.recipients.length);
        for (uint256 i; i < r.length; i++) {
            r[i] = RecipientData({ recipient: c.recipients[i], permission: 2 });
        }
        p = new PolicyConfig[](4);
        p[0] = PolicyConfig(c.token, TRANSFER, 0, c.erc20TransferPolicy, abi.encode(r));
        p[1] = PolicyConfig(c.multiSend, MULTISEND, 1, c.multiSendPolicy, "");
        p[2] = PolicyConfig(c.safe, SWAP_OWNER, 0, c.increasedThresholdPolicy, abi.encode(uint256(1)));
        p[3] = PolicyConfig(c.safe, DISABLE_MODULE, 0, c.ownerOnlyPolicy, "");
    }

    /// Architecture A: owners only may (un)assign roles - never a module.
    function rolesPolicies(address roles, address ownerOnlyPolicy)
        internal
        pure
        returns (PolicyConfig[] memory p)
    {
        p = new PolicyConfig[](1);
        p[0] = PolicyConfig(roles, ASSIGN_ROLES, 0, ownerOnlyPolicy, "");
    }

    struct SessionsEntries {
        address smartSession;
        address safe7579;
        address dcUtil; // Safe7579DCUtil, deployed by the Safe7579 constructor (CREATE nonce 1)
        address entryPoint;
        address ownerOnlyPolicy;
        address allowedModulePolicy;
        address nativeTransferPolicy;
        address batchPolicy; // Safe7579BatchPolicy
        bytes4 enableSessions;
        bytes4 removeSession;
        bytes4 validateUserOp;
        bytes4 batchedExecute;
    }

    /**
     * Architecture B: Safe7579 issues five kinds of module transactions, and each needs an entry:
     *   SmartSession.enableSessions / removeSession   OwnerOnlyPolicy
     *   SmartSession.validateUserOp                   AllowedModulePolicy(Safe7579)  (validation phase)
     *   EntryPoint (plain ETH)                        NativeTransferPolicy           (prefund)
     *   DCUtil.execute(Execution[])  DELEGATECALL     Safe7579BatchPolicy            (7579 batches)
     *   (single executions reuse the common entries; module installs stay denied)
     */
    function sessionsPolicies(SessionsEntries memory s) internal pure returns (PolicyConfig[] memory p) {
        p = new PolicyConfig[](5);
        p[0] = PolicyConfig(s.smartSession, s.enableSessions, 0, s.ownerOnlyPolicy, "");
        p[1] = PolicyConfig(s.smartSession, s.removeSession, 0, s.ownerOnlyPolicy, "");
        p[2] = PolicyConfig(
            s.smartSession, s.validateUserOp, 0, s.allowedModulePolicy, abi.encode(s.safe7579, true)
        );
        p[3] = PolicyConfig(s.entryPoint, bytes4(0), 0, s.nativeTransferPolicy, "");
        p[4] = PolicyConfig(s.dcUtil, s.batchedExecute, 1, s.batchPolicy, "");
    }

    function concat(PolicyConfig[] memory a, PolicyConfig[] memory b)
        internal
        pure
        returns (PolicyConfig[] memory c)
    {
        c = new PolicyConfig[](a.length + b.length);
        for (uint256 i; i < a.length; i++) {
            c[i] = a[i];
        }
        for (uint256 i; i < b.length; i++) {
            c[a.length + i] = b[i];
        }
    }

    /// Owner tx #N: `guard.configureImmediately(configs)` - only possible while no guard is installed.
    function configureImmediately(PolicyConfig[] memory configs) internal pure returns (bytes memory) {
        return
            abi.encodeWithSignature("configureImmediately((address,bytes4,uint8,address,bytes)[])", configs);
    }

    /// Owner tx #N+1 (DELEGATECALL MultiSendCallOnly): install the guard as BOTH guards, atomically.
    function installGuards(address safe, address guard)
        internal
        pure
        returns (bytes memory multiSendTransactions)
    {
        multiSendTransactions = abi.encodePacked(
            multiSendTx(0, safe, 0, abi.encodeWithSignature("setGuard(address)", guard)),
            multiSendTx(0, safe, 0, abi.encodeWithSignature("setModuleGuard(address)", guard))
        );
    }

    /**
     * Zodiac Roles scope for `token.transfer(to, amount)`:
     *   to     ∈ recipients                         (Or of EqualTo)
     *   amount <  maxPerTx + 1  AND  WithinAllowance(allowanceKey)
     */
    function rolesTransferScope(address[] memory recipients, uint256 maxPerTx, bytes32 allowanceKey)
        internal
        pure
        returns (ConditionFlat[] memory c)
    {
        uint256 n = recipients.length;
        c = new ConditionFlat[](5 + n);
        c[0] = ConditionFlat(0, ParameterType.Calldata, Operator.Matches, "");
        c[1] = ConditionFlat(0, ParameterType.None, Operator.Or, ""); // param 0: to
        c[2] = ConditionFlat(0, ParameterType.None, Operator.And, ""); // param 1: amount
        for (uint256 i; i < n; i++) {
            c[3 + i] = ConditionFlat(1, ParameterType.Static, Operator.EqualTo, abi.encode(recipients[i]));
        }
        c[3 + n] = ConditionFlat(2, ParameterType.Static, Operator.LessThan, abi.encode(maxPerTx + 1));
        c[4 + n] = ConditionFlat(2, ParameterType.Static, Operator.WithinAllowance, abi.encode(allowanceKey));
    }

    struct RolesParams {
        address safe;
        address roles;
        address multiSend;
        address unwrapper; // MultiSendUnwrapper
        address token;
        address[] recipients;
        uint256 maxPerTx;
        uint256 maxPerDay;
        bytes32 role;
        bytes32 allowanceKey;
    }

    /// Owner tx (DELEGATECALL MultiSendCallOnly): enable Roles on the Safe and define the role.
    function rolesAttach(RolesParams memory p) internal pure returns (bytes memory multiSendTransactions) {
        multiSendTransactions = abi.encodePacked(
            multiSendTx(0, p.safe, 0, abi.encodeWithSignature("enableModule(address)", p.roles)),
            multiSendTx(
                0,
                p.roles,
                0,
                abi.encodeWithSignature(
                    "setTransactionUnwrapper(address,bytes4,address)", p.multiSend, MULTISEND, p.unwrapper
                )
            ),
            multiSendTx(
                0, p.roles, 0, abi.encodeWithSignature("scopeTarget(bytes32,address)", p.role, p.token)
            ),
            multiSendTx(
                0,
                p.roles,
                0,
                abi.encodeWithSignature(
                    "scopeFunction(bytes32,address,bytes4,(uint8,uint8,uint8,bytes)[],uint8)",
                    p.role,
                    p.token,
                    TRANSFER,
                    rolesTransferScope(p.recipients, p.maxPerTx, p.allowanceKey),
                    uint8(ExecutionOptions.None)
                )
            ),
            multiSendTx(
                0,
                p.roles,
                0,
                // balance, maxRefill, refill = maxPerDay; period 1 day; timestamp 0 = now
                abi.encodeWithSignature(
                    "setAllowance(bytes32,uint128,uint128,uint128,uint64,uint64)",
                    p.allowanceKey,
                    uint128(p.maxPerDay),
                    uint128(p.maxPerDay),
                    uint128(p.maxPerDay),
                    uint64(1 days),
                    uint64(0)
                )
            )
        );
    }

    /// Owner tx: grant (`member`) or revoke (`!member`) the role for `operator`.
    function rolesAssign(address operator, bytes32 role, bool member) internal pure returns (bytes memory) {
        bytes32[] memory r = new bytes32[](1);
        r[0] = role;
        bool[] memory m = new bool[](1);
        m[0] = member;
        return abi.encodeWithSelector(ASSIGN_ROLES, operator, r, m);
    }

    struct OperatorSession {
        address validator; // OwnableValidator
        address signer; // the session (operator) key
        address token;
        address[] recipients;
        uint256 maxPerTx;
        uint256 maxPerDay;
        uint48 validUntil;
        uint128 gasUnitsLimit;
        uint128 gasCostLimit;
        uint128 maxFeePerGas;
        SessionSetup.Policies policies;
    }

    /// Architecture B: the same mandate as `rolesTransferScope`, as a SmartSessions session.
    function operatorSession(OperatorSession memory o) internal pure returns (Session memory) {
        FunctionWhitelistPolicy.Permission[] memory perms = new FunctionWhitelistPolicy.Permission[](1);
        perms[0] = FunctionWhitelistPolicy.Permission({ target: o.token, selector: TRANSFER });
        SpendingLimitPolicy.AssetLimit[] memory limits = new SpendingLimitPolicy.AssetLimit[](1);
        limits[0] = SpendingLimitPolicy.AssetLimit({
            asset: o.token, maxPerTx: uint128(o.maxPerTx), maxPerPeriod: uint128(o.maxPerDay), period: 1 days
        });
        SessionSetup.SessionParams memory p;
        p.validator = ISessionValidator(o.validator);
        p.signer = o.signer;
        p.salt = bytes32(uint256(uint160(o.signer)));
        p.validUntil = o.validUntil;
        p.gasUnitsLimit = o.gasUnitsLimit;
        p.gasCostLimit = o.gasCostLimit;
        p.maxFeePerGas = o.maxFeePerGas;
        p.allowNativeTransfers = false;
        p.permissions = perms;
        p.recipients = o.recipients;
        p.limits = limits;
        return SessionSetup.exchangeSession(p, o.policies);
    }

    function multiSendTx(uint8 op, address to, uint256 value, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(op, to, value, data.length, data);
    }
}
