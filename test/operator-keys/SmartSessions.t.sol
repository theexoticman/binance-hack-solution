// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { OperatorKeySuite } from "./OperatorKeySuite.sol";
import { SmartSessionsHarness } from "./utils/SmartSessionsHarness.sol";
import { ISafe150, PolicyConfig, IPolicyGuard } from "./utils/OperatorKeyBase.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { Safe7579 } from "safe7579/Safe7579.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { IValidator } from "erc7579/interfaces/IERC7579Module.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { PermissionId, Session, ActionData, PolicyData } from "smartsessions/DataTypes.sol";
import { Execution7579 } from "src/policies/engine/Safe7579BatchPolicy.sol";
import { Enum } from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";

interface IPolicyHook {
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        address module,
        bytes calldata context,
        uint256 access
    ) external returns (bytes4);
}

/// @dev A minimal ERC-7579 executor: once installed it may call `executeFromExecutor` freely.
contract RogueExecutor {
    function onInstall(bytes calldata) external { }
    function onUninstall(bytes calldata) external { }

    function isModuleType(uint256) external pure returns (bool) {
        return true; // claims to be an executor (2), fallback (3) and hook (4)
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }
}

/// @notice Architecture B (Rhinestone Smart Sessions): shared suite + 7579/4337-specific checks.
contract SmartSessionsOperatorKeyTest is SmartSessionsHarness, OperatorKeySuite {
    function test_B_policyEngineSeesSafe7579Module_notSessionKey() public {
        bytes memory data = abi.encodeCall(usdc.transfer, (alice, 1e6));
        (uint256 access,) = guard.getPolicy(address(safe), address(usdc), data, 0);
        vm.expectCall(
            erc20TransferPolicy,
            abi.encodeCall(
                IPolicyHook.checkTransaction,
                (address(safe), address(usdc), 0, data, 0, address(safe7579), "", access)
            )
        );
        (bool ok,) = _operatorExec(operator, Exec(address(usdc), 0, data, 0));
        assertTrue(ok);
    }

    /// @dev Even the validation phase is a policy-checked module transaction.
    function test_B_validationPhaseIsAModuleTransaction() public {
        vm.expectCall(
            allowedModulePolicy,
            abi.encodeWithSelector(
                IPolicyHook.checkTransaction.selector, address(safe), address(smartSession)
            )
        );
        (bool ok,) = _operatorExec(operator, _transfer(usdc, alice, 1e6));
        assertTrue(ok);
    }

    function test_B_withoutValidatorEntry_noUserOpCanValidate() public {
        // Same deployment, but the owners forgot the validateUserOp entry: every session is dead.
        PolicyConfig[] memory remove = new PolicyConfig[](1);
        remove[0] = PolicyConfig(address(smartSession), IValidator.validateUserOp.selector, 0, address(0), "");
        _applyDelayed(remove);
        Effects memory before = _effects();
        (bool ok, bytes memory reason) = _operatorExec(operator, _transfer(usdc, alice, 1e6));
        assertFalse(ok);
        assertEq(bytes4(reason), IEntryPoint.FailedOpWithRevert.selector, "fails in validation");
        _assertNoEffects(before);
    }

    function test_B_expiredSession_isRejected() public {
        vm.warp(block.timestamp + OPERATOR_TTL + 1);
        Effects memory before = _effects();
        (bool ok, bytes memory reason) = _operatorExec(operator, _transfer(usdc, alice, 1e6));
        assertFalse(ok);
        assertEq(reason, abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
        _assertNoEffects(before);
    }

    function test_B_userOpSignedBeforeRevocation_isRejected() public {
        PackedUserOperation memory op =
            _signUserOp(operator, _userOp(_singleCallData(_transfer(usdc, alice, 1e6))));
        Exec memory r = _revokeOperatorTx(operator.addr);
        _ownerExecOrFail(r.to, 0, r.data, 0);
        Effects memory before = _effects();
        (bool ok,) = _submit(op);
        assertFalse(ok);
        _assertNoEffects(before);
    }

    function test_B_userOpCannotBeReplayed() public {
        PackedUserOperation memory op =
            _signUserOp(operator, _userOp(_singleCallData(_transfer(usdc, alice, 5e6))));
        (bool ok,) = _submit(op);
        assertTrue(ok);
        Effects memory before = _effects();
        (ok,) = _submit(op);
        assertFalse(ok);
        _assertNoEffects(before);
    }

    function test_B_prefundIsAPolicyCheckedModuleTransaction() public {
        opMaxFee = 1 gwei;
        vm.expectCall(
            nativeTransferPolicy,
            abi.encodeWithSelector(IPolicyHook.checkTransaction.selector, address(safe), ENTRYPOINT_V07)
        );
        uint256 ethBefore = address(safe).balance;
        (bool ok, bytes memory reason) = _operatorExec(operator, _transfer(usdc, alice, 1e6));
        if (!ok) _bubble(reason);
        assertLt(address(safe).balance, ethBefore, "prefund paid");
        assertEq(usdc.balanceOf(alice), 1e6);
    }

    function test_B_sessionCannotInstallExecutorOrHook() public {
        RogueExecutor rogue = new RogueExecutor();
        uint256[2] memory types = [uint256(2), 4]; // executor, hook
        bytes[2] memory initData = [bytes(""), abi.encode(uint8(0), bytes4(0), bytes(""))]; // hook: GLOBAL
        for (uint256 i; i < types.length; i++) {
            Effects memory before = _effects();
            bytes memory install =
                abi.encodeCall(IERC7579Account.installModule, (types[i], address(rogue), initData[i]));
            (bool ok, bytes memory reason) = _submit(_signUserOp(operator, _userOp(install)));
            assertFalse(ok, "session installed a module");
            _assertNoEffects(before);
            // Module compromise: even reached as a self-call (onlyEntryPointOrSelf satisfied), Safe7579
            // runs onInstall through a module transaction that the engine has no policy for.
            vm.prank(address(safe));
            (ok, reason) = address(safe).call(install);
            assertFalse(ok, "self-call installed a module");
            assertTrue(_isPolicyEngineDenial(reason), "not denied by the Policy Engine");
            _assertNoEffects(before);
        }
    }

    /// @dev Structural property: SmartSessions refuses to let any session act on SmartSession itself.
    function test_B_sessionCannotBeGrantedSmartSessionActions() public {
        PolicyData[] memory sudo = new PolicyData[](1);
        sudo[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        Session memory s = _session(attacker);
        s.actions = new ActionData[](1);
        s.actions[0] = ActionData(ISmartSession.enableSessions.selector, address(smartSession), sudo);
        Session[] memory list = new Session[](1);
        list[0] = s;
        vm.prank(address(safe)); // even the account itself cannot configure this
        vm.expectRevert(ISmartSession.InvalidActionId.selector);
        smartSession.enableSessions(list);
    }

    function test_B_ownersCannotInstallExecutorWithoutPolicyEntry() public {
        RogueExecutor rogue = new RogueExecutor();
        Effects memory before = _effects();
        (bool ok, bytes memory reason) = _ownerExec(
            address(safe), 0, abi.encodeCall(IERC7579Account.installModule, (2, address(rogue), "")), 0
        );
        assertFalse(ok);
        assertEq(reason, _accessDenied(address(0)));
        _assertNoEffects(before);
    }

    function test_B_directCallsToSafe7579Entrypoints_revert() public {
        Effects memory before = _effects();
        bytes memory exec = abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(attacker, 1 ether, ""))
        );
        vm.startPrank(operator.addr);
        (bool ok,) = address(safe).call(exec); // via the Safe's fallback handler
        assertFalse(ok);
        (ok,) = address(safe7579).call(exec); // the adapter directly
        assertFalse(ok);
        vm.stopPrank();
        _assertNoEffects(before);
    }

    function test_B_userOpWithoutSessionValidator_fallsBackToOwnerSignatures() public {
        // nonce key 0 -> Safe7579 uses Safe.checkSignatures: a session key is not an owner.
        PackedUserOperation memory op = _userOp(_singleCallData(Exec(attacker, 1 ether, "", 0)));
        op.nonce = entryPoint.getNonce(address(safe), 0);
        op.signature =
            abi.encodePacked(uint48(0), uint48(0), _signDigest(operator, entryPoint.getUserOpHash(op)));
        Effects memory before = _effects();
        (bool ok,) = _submit(op);
        assertFalse(ok);
        _assertNoEffects(before);
    }

    /// @dev The pitfall Safe7579BatchPolicy exists for: allowing the DCUtil delegatecall wholesale
    ///      (an AllowPolicy, or AllowedModulePolicy(Safe7579)) lets every batch element run unchecked.
    function test_B_finding_allowingDcUtilWholesaleIsABypass() public {
        PolicyConfig[] memory naive = new PolicyConfig[](1);
        naive[0] = PolicyConfig(
            dcUtil,
            bytes4(keccak256("execute((address,uint256,bytes)[])")),
            1,
            allowedModulePolicy,
            abi.encode(address(safe7579), true)
        );
        _applyDelayed(naive);

        Exec[] memory es = new Exec[](1);
        es[0] = Exec(attacker, 1 ether, "", 0);
        (bool ok,) = _asModule(_batchAsModuleTx(es)); // a compromised / misconfigured operator layer
        assertTrue(ok, "expected the naive configuration to be bypassable");
        assertEq(attacker.balance, 1 ether, "ETH left the Safe with no policy check");
    }

    function test_B_killSwitch_ownersDisableSafe7579() public {
        _ownerExecOrFail(
            address(safe), 0, abi.encodeCall(ISafe150.disableModule, (SENTINEL, address(safe7579))), 0
        );
        Effects memory before = _effects();
        (bool ok,) = _operatorExec(operator, _transfer(usdc, alice, 1e6));
        assertFalse(ok);
        _assertNoEffects(before);
    }

    function _applyDelayed(PolicyConfig[] memory cfg) internal {
        bytes32 root = keccak256(abi.encode(cfg));
        _ownerExecOrFail(address(guard), 0, abi.encodeCall(IPolicyGuard.requestConfiguration, (root)), 0);
        vm.warp(block.timestamp + POLICY_DELAY);
        _ownerExecOrFail(address(guard), 0, abi.encodeCall(IPolicyGuard.applyConfiguration, (cfg)), 0);
    }
}
