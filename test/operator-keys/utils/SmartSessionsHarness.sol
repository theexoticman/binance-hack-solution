// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm } from "forge-std/Vm.sol";
import { OperatorKeyBase, ISafe150, PolicyConfig } from "./OperatorKeyBase.sol";

// ERC-4337 v0.7 EntryPoint at the canonical address (Safe7579 hard-codes it)
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";

// Safe7579 adapter v1.0.0, SmartSessions @ f5aaf86, OwnableValidator (same pins as the existing suite)
import { Safe7579 } from "safe7579/Safe7579.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import {
    ModeLib,
    ModeCode,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    MODE_DEFAULT,
    ModePayload
} from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { IValidator } from "erc7579/interfaces/IERC7579Module.sol";
import { SmartSession } from "smartsessions/SmartSession.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { EncodeLib } from "smartsessions/lib/EncodeLib.sol";
import { TimeFramePolicy } from "smartsessions/external/policies/TimeFramePolicy.sol";
import { SimpleGasPolicy } from "smartsessions/external/policies/SimpleGasPolicy.sol";
import { SudoPolicy } from "smartsessions/external/policies/SudoPolicy.sol";
import { ISessionValidator } from "smartsessions/interfaces/ISessionValidator.sol";
import {
    Session,
    PermissionId,
    ActionData,
    PolicyData,
    ERC7739Context,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG
} from "smartsessions/DataTypes.sol";
import { OwnableValidator } from "core-modules/OwnableValidator/OwnableValidator.sol";

// This repository: the existing session policies and calldata builders, reused unchanged
import { FunctionWhitelistPolicy } from "src/policies/FunctionWhitelistPolicy.sol";
import { AddressWhitelistPolicy } from "src/policies/AddressWhitelistPolicy.sol";
import { SpendingLimitPolicy } from "src/policies/SpendingLimitPolicy.sol";
import { GasFeeCapPolicy } from "src/policies/GasFeeCapPolicy.sol";
import {
    Safe7579BatchPolicy,
    IBatchedExecUtil,
    Execution7579
} from "src/policies/engine/Safe7579BatchPolicy.sol";
import { SessionSetup } from "script/lib/SessionSetup.sol";
import { OperatorKeySetup } from "script/lib/OperatorKeySetup.sol";

/**
 * @notice Architecture B:  Session key -> EntryPoint -> Safe7579 -> SmartSession -> Safe -> Safe Policy Engine
 *
 *   Safe7579 is the Safe's ONLY module and its fallback handler; SmartSession its only 7579 validator.
 *   Session per operator key (OwnableValidator 1-of-[key]):
 *     userOp policies: TimeFramePolicy (validUntil = now + 30 days), SimpleGasPolicy, GasFeeCapPolicy
 *     catch-all action: FunctionWhitelistPolicy [(USDC, transfer)], no native transfers, value 0
 *                       AddressWhitelistPolicy  {alice, bob}
 *                       SpendingLimitPolicy     USDC 1000e6 per tx, 3000e6 per UTC day
 *   (Same mandate as Architecture A; SessionSetup.exchangeSession builds it.)
 *
 *   The Policy Engine sees FIVE kinds of module transactions from Safe7579, each needing an entry:
 *     the validator call (SmartSession.validateUserOp), the prefund (ETH to the EntryPoint), single
 *     executions, batches (DELEGATECALL to Safe7579's DCUtil), and module (un)installation.
 */
abstract contract SmartSessionsHarness is OperatorKeyBase {
    address internal constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    uint128 internal constant SESSION_GAS_UNITS = 1_000_000_000;
    uint128 internal constant SESSION_GAS_COST = 0.1 ether;
    uint128 internal constant SESSION_MAX_FEE = 100 gwei;

    IEntryPoint internal entryPoint;
    Safe7579 internal safe7579;
    address internal dcUtil; // Safe7579DCUtil, created by the adapter's constructor
    SmartSession internal smartSession;
    OwnableValidator internal ownableValidator;
    TimeFramePolicy internal timeFramePolicy;
    SimpleGasPolicy internal gasPolicy;
    GasFeeCapPolicy internal gasFeeCapPolicy;
    FunctionWhitelistPolicy internal functionPolicy;
    AddressWhitelistPolicy internal addressPolicy;
    SpendingLimitPolicy internal spendingPolicy;
    Safe7579BatchPolicy internal batchPolicy;
    SudoPolicy internal sudoPolicy; // fault injection only

    mapping(address key => PermissionId) internal permissionOf;

    // Gas parameters of the user operations (0 fees keep balance assertions exact; see prefund test).
    uint128 internal opMaxFee;

    function _deployArchitecture() internal virtual override {
        vm.etch(ENTRYPOINT_V07, address(new EntryPoint()).code);
        entryPoint = IEntryPoint(ENTRYPOINT_V07);
        safe7579 = new Safe7579();
        dcUtil = vm.computeCreateAddress(address(safe7579), 1);
        require(dcUtil.code.length != 0, "DCUtil not found");
        smartSession = new SmartSession();
        ownableValidator = new OwnableValidator();
        timeFramePolicy = new TimeFramePolicy();
        gasPolicy = new SimpleGasPolicy();
        gasFeeCapPolicy = new GasFeeCapPolicy();
        functionPolicy = new FunctionWhitelistPolicy();
        addressPolicy = new AddressWhitelistPolicy();
        spendingPolicy = new SpendingLimitPolicy();
        batchPolicy = new Safe7579BatchPolicy();
        sudoPolicy = new SudoPolicy();
    }

    function _attachArchitecture() internal virtual override {
        _ownerExecOrFail(
            address(multiSend),
            0,
            abi.encodeWithSignature(
                "multiSend(bytes)",
                SessionSetup.attachSafe7579(address(safe), address(safe7579), address(smartSession))
            ),
            1
        );
    }

    function _registerInitialOperator(address op) internal virtual override {
        Exec memory r = _registerOperatorTx(op);
        _ownerExecOrFail(r.to, r.value, r.data, r.operation);
    }

    function _architecturePolicies() internal view virtual override returns (PolicyConfig[] memory) {
        return OperatorKeySetup.sessionsPolicies(
            OperatorKeySetup.SessionsEntries({
                smartSession: address(smartSession),
                safe7579: address(safe7579),
                dcUtil: dcUtil,
                entryPoint: ENTRYPOINT_V07,
                ownerOnlyPolicy: ownerOnlyPolicy,
                allowedModulePolicy: allowedModulePolicy,
                nativeTransferPolicy: nativeTransferPolicy,
                batchPolicy: address(batchPolicy),
                enableSessions: ISmartSession.enableSessions.selector,
                removeSession: ISmartSession.removeSession.selector,
                validateUserOp: IValidator.validateUserOp.selector,
                batchedExecute: IBatchedExecUtil.execute.selector
            })
        );
    }

    function _operatorModule() internal view virtual override returns (address) {
        return address(safe7579);
    }

    /*//////////////////////////////////////////////////////////////
                               SESSIONS
    //////////////////////////////////////////////////////////////*/

    function _session(address key) internal view returns (Session memory) {
        address[] memory recipients = new address[](2);
        recipients[0] = alice;
        recipients[1] = bob;
        return OperatorKeySetup.operatorSession(
            OperatorKeySetup.OperatorSession({
                validator: address(ownableValidator),
                signer: key,
                token: address(usdc),
                recipients: recipients,
                maxPerTx: MAX_PER_TX,
                maxPerDay: MAX_PER_DAY,
                validUntil: uint48(block.timestamp) + OPERATOR_TTL,
                gasUnitsLimit: SESSION_GAS_UNITS,
                gasCostLimit: SESSION_GAS_COST,
                maxFeePerGas: SESSION_MAX_FEE,
                policies: SessionSetup.Policies({
                    timeFrame: address(timeFramePolicy),
                    gas: address(gasPolicy),
                    gasFeeCap: address(gasFeeCapPolicy),
                    functionWhitelist: address(functionPolicy),
                    addressWhitelist: address(addressPolicy),
                    spendingLimit: address(spendingPolicy)
                })
            })
        );
    }

    function _registerOperatorTx(address op) internal virtual override returns (Exec memory) {
        Session[] memory list = new Session[](1);
        list[0] = _session(op);
        permissionOf[op] = smartSession.getPermissionId(list[0]);
        return Exec(address(smartSession), 0, abi.encodeCall(ISmartSession.enableSessions, (list)), 0);
    }

    function _revokeOperatorTx(address op) internal virtual override returns (Exec memory) {
        return
            Exec(address(smartSession), 0, abi.encodeCall(ISmartSession.removeSession, (permissionOf[op])), 0);
    }

    /// @dev Fault injection: a sudo session for `k` (SudoPolicy on user-op and catch-all action).
    ///      SmartSessions cannot express DELEGATECALL at all, so that returns false.
    function _openOperatorLayer(Key memory k, address target, uint8 operation)
        internal
        virtual
        override
        returns (bool)
    {
        if (operation == 1) return false; // UnsupportedCallType: structurally impossible for sessions
        // ConfigLib rejects any action targeting SmartSession itself (InvalidActionId), and the
        // catch-all action never matches it (NoPoliciesSet): a session cannot be granted that.
        if (target == address(smartSession)) return false;
        PolicyData[] memory sudo = new PolicyData[](1);
        sudo[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData(FALLBACK_TARGET_SELECTOR_FLAG, FALLBACK_TARGET_FLAG, sudo);
        address[] memory signers = new address[](1);
        signers[0] = k.addr;
        Session memory s;
        s.sessionValidator = ISessionValidator(address(ownableValidator));
        s.sessionValidatorInitData = abi.encode(uint256(1), signers);
        s.salt = keccak256(abi.encode("sudo", k.addr, target));
        s.userOpPolicies = sudo;
        s.erc7739Policies.allowedERC7739Content = new ERC7739Context[](0);
        s.erc7739Policies.erc1271Policies = new PolicyData[](0);
        s.actions = actions;
        Session[] memory list = new Session[](1);
        list[0] = s;
        vm.prank(address(safe));
        smartSession.enableSessions(list);
        permissionOf[k.addr] = smartSession.getPermissionId(s);
        return true;
    }

    function _archState() internal view virtual override returns (bytes32) {
        Safe7579 account = Safe7579(payable(address(safe)));
        (address[] memory validators,) = account.getValidatorsPaginated(SENTINEL, 20);
        (address[] memory executors,) = account.getExecutorsPaginated(SENTINEL, 20);
        return keccak256(
            abi.encode(
                validators,
                executors,
                account.getActiveHook(),
                smartSession.isPermissionEnabled(permissionOf[operator.addr], address(safe)),
                smartSession.isPermissionEnabled(
                    smartSession.getPermissionId(_session(attacker)), address(safe)
                )
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                              USER OPS
    //////////////////////////////////////////////////////////////*/

    function _singleCallData(Exec memory e) internal pure returns (bytes memory) {
        if (e.operation == 1) {
            ModeCode mode =
                ModeLib.encode(CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0));
            return abi.encodeCall(IERC7579Account.execute, (mode, abi.encodePacked(e.to, e.data)));
        }
        return abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(e.to, e.value, e.data))
        );
    }

    function _toExecutions(Exec[] memory es) internal pure returns (Execution[] memory x) {
        x = new Execution[](es.length);
        for (uint256 i; i < es.length; i++) {
            require(es[i].operation == 0, "7579 batches contain CALLs only");
            x[i] = Execution({ target: es[i].to, value: es[i].value, callData: es[i].data });
        }
    }

    function _userOp(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        uint192 key = uint192(bytes24(bytes20(address(smartSession))));
        op.sender = address(safe);
        op.nonce = entryPoint.getNonce(address(safe), key);
        op.callData = callData;
        op.accountGasLimits = bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000)));
        op.preVerificationGas = 100_000;
        op.gasFees = bytes32(abi.encodePacked(opMaxFee, opMaxFee));
    }

    function _signUserOp(Key memory k, PackedUserOperation memory op)
        internal
        view
        returns (PackedUserOperation memory)
    {
        op.signature = EncodeLib.encodeUse(permissionOf[k.addr], _signDigest(k, entryPoint.getUserOpHash(op)));
        return op;
    }

    /// @dev Bundles one op. Validation failures revert handleOps; execution failures do not (the
    ///      EntryPoint emits UserOperationEvent(success=false) + UserOperationRevertReason) - so the
    ///      outcome is read from the events, never from handleOps' status alone.
    function _submit(PackedUserOperation memory op) internal returns (bool ok, bytes memory reason) {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        bytes32 h = entryPoint.getUserOpHash(op);
        vm.recordLogs();
        vm.prank(relayer, relayer);
        (bool called, bytes memory ret) =
            address(entryPoint).call(abi.encodeCall(IEntryPoint.handleOps, (ops, relayer)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        if (!called) return (false, ret);
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IEntryPoint.UserOperationRevertReason.selector && logs[i].topics[1] == h)
            {
                (, reason) = abi.decode(logs[i].data, (uint256, bytes));
            }
            if (logs[i].topics[0] == IEntryPoint.UserOperationEvent.selector && logs[i].topics[1] == h) {
                (, ok,,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
            }
        }
    }

    function _operatorExec(Key memory k, Exec memory e)
        internal
        virtual
        override
        returns (bool, bytes memory)
    {
        return _submit(_signUserOp(k, _userOp(_singleCallData(e))));
    }

    function _operatorBatch(Key memory k, Exec[] memory es)
        internal
        virtual
        override
        returns (bool, bytes memory)
    {
        bytes memory callData = abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(_toExecutions(es)))
        );
        return _submit(_signUserOp(k, _userOp(callData)));
    }

    function _batchAsModuleTx(Exec[] memory es) internal view virtual override returns (Exec memory) {
        Execution7579[] memory x = new Execution7579[](es.length);
        for (uint256 i; i < es.length; i++) {
            x[i] = Execution7579({ target: es[i].to, value: es[i].value, callData: es[i].data });
        }
        return Exec(dcUtil, 0, abi.encodeCall(IBatchedExecUtil.execute, (x)), 1);
    }
}
