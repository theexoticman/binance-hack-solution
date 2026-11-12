// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { OperatorKeySuite } from "./OperatorKeySuite.sol";
import { ZodiacRolesHarness } from "./utils/ZodiacRolesHarness.sol";
import { OperatorKeyBase, ISafe150 } from "./utils/OperatorKeyBase.sol";
import { Roles } from "zodiac-roles/Roles.sol";
import { ExecutionOptions } from "zodiac-roles/Types.sol";
import { Enum as ZodiacEnum } from "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import {
    CompatibilityFallbackHandler
} from "@safe-global/safe-smart-account/contracts/handler/CompatibilityFallbackHandler.sol";

/// @dev ABI of the upstream policy hook, to observe exactly what the Policy Engine passes.
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

/// @notice Architecture A (Zodiac Roles): shared suite + Roles-specific checks.
contract ZodiacRolesOperatorKeyTest is ZodiacRolesHarness, OperatorKeySuite {
    function _exec(Key memory k, Exec memory e) internal returns (bool, bytes memory) {
        return _operatorExec(k, e);
    }

    function test_A_policyEngineSeesRolesModule_notOperatorKey() public {
        bytes memory data = abi.encodeCall(usdc.transfer, (alice, 1e6));
        (uint256 access,) = guard.getPolicy(address(safe), address(usdc), data, 0);
        vm.expectCall(
            erc20TransferPolicy,
            abi.encodeCall(
                IPolicyHook.checkTransaction,
                (address(safe), address(usdc), 0, data, 0, address(roles), "", access)
            )
        );
        (bool ok,) = _exec(operator, Exec(address(usdc), 0, data, 0));
        assertTrue(ok);
    }

    function test_A_directEoaSubmission_alsoWorks() public {
        vm.prank(operator.addr);
        roles.execTransactionWithRole(
            address(usdc), 0, abi.encodeCall(usdc.transfer, (bob, 7e6)), ZodiacEnum.Operation.Call, ROLE, true
        );
        assertEq(usdc.balanceOf(bob), 7e6);
    }

    function test_A_signedPayloadCannotBeReplayed() public {
        bytes memory signedCall = _signedRolesCall(
            operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 5e6)), 0)
        );
        vm.prank(relayer);
        (bool ok,) = address(roles).call(signedCall);
        assertTrue(ok);
        Effects memory before = _effects();
        vm.prank(attacker);
        (ok,) = address(roles).call(signedCall);
        assertFalse(ok, "replayed");
        _assertNoEffects(before);
        assertEq(usdc.balanceOf(alice), 5e6);
    }

    function test_A_payloadSignedBeforeRevocation_isRejected() public {
        bytes memory signedCall = _signedRolesCall(
            operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 5e6)), 0)
        );
        Exec memory r = _revokeOperatorTx(operator.addr);
        _ownerExecOrFail(r.to, 0, r.data, 0);
        Effects memory before = _effects();
        vm.prank(relayer);
        (bool ok, bytes memory reason) = address(roles).call(signedCall);
        assertFalse(ok);
        assertEq(bytes4(reason), bytes4(keccak256("NoMembership()")));
        _assertNoEffects(before);
    }

    /// @dev Verified absence: v2.1.1 role membership has no expiry. Bounding an operator in time needs
    ///      an owner transaction (or a custom condition checker contract).
    function test_A_finding_noNativeOperatorExpiry() public {
        vm.warp(block.timestamp + 365 days);
        (bool ok,) = _exec(operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 1e6)), 0));
        assertTrue(ok, "operator expired");
    }

    function test_A_defaultRolePathHasNoPermissions() public {
        Effects memory before = _effects();
        vm.prank(operator.addr);
        (bool ok,) = address(roles)
            .call(
                abi.encodeCall(
                    Roles.execTransactionFromModule,
                    (address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 1e6)), ZodiacEnum.Operation.Call)
                )
            );
        assertFalse(ok);
        _assertNoEffects(before);
    }

    function test_A_operatorCannotCallRolesAdminDirectly() public {
        Effects memory before = _effects();
        bytes32[] memory r = new bytes32[](1);
        r[0] = ROLE;
        bool[] memory m = new bool[](1);
        m[0] = true;
        vm.prank(operator.addr);
        (bool ok,) = address(roles).call(abi.encodeCall(Roles.assignRoles, (attacker, r, m)));
        assertFalse(ok, "onlyOwner bypassed");
        _assertNoEffects(before);
    }

    function test_A_fallbackHandlerExposesNoExecution() public {
        Effects memory before = _effects();
        vm.startPrank(operator.addr);
        (bool ok,) = address(safe)
            .call(
                abi.encodeCall(
                    CompatibilityFallbackHandler.simulate,
                    (address(usdc), abi.encodeCall(usdc.transfer, (attacker, 1)))
                )
            );
        assertFalse(ok);
        (ok,) = address(safe).call(abi.encodePacked(bytes4(0xdeadbeef), abi.encode(attacker)));
        vm.stopPrank();
        _assertNoEffects(before);
    }

    function test_A_killSwitch_ownersDisableRoles() public {
        _ownerExecOrFail(
            address(safe), 0, abi.encodeCall(ISafe150.disableModule, (SENTINEL, address(roles))), 0
        );
        Effects memory before = _effects();
        (bool ok,) = _exec(operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 1e6)), 0));
        assertFalse(ok);
        _assertNoEffects(before);
    }

    /// @dev Structural property: every call to (MultiSend, multiSend) is routed through the registered
    ///      unwrapper, which accepts DELEGATECALL batches only and authorizes each element - even when
    ///      the role has blanket clearance on the MultiSend target.
    function test_A_multiSendIsAlwaysUnwrapped() public {
        vm.prank(address(safe));
        roles.allowTarget(ROLE, address(multiSend), ExecutionOptions.Both);
        Exec[] memory leaf = new Exec[](1);
        leaf[0] = Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (attacker, 1e6)), 0);
        Exec memory batch = _multiSendExec(leaf);
        Effects memory before = _effects();
        (bool ok, bytes memory reason) = _exec(operator, batch); // DELEGATECALL: element checked
        assertFalse(ok);
        assertEq(bytes4(reason), bytes4(keccak256("ConditionViolation(uint8,bytes32)")));
        batch.operation = 0;
        (ok, reason) = _exec(operator, batch); // CALL: the unwrapper reverts (UnsupportedMode)
        assertFalse(ok);
        assertEq(bytes4(reason), bytes4(keccak256("MalformedMultiEntrypoint()")));
        _assertNoEffects(before);
    }
}
