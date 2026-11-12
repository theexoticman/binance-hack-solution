// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { OperatorKeyBase } from "./utils/OperatorKeyBase.sol";
import { ZodiacRolesHarness } from "./utils/ZodiacRolesHarness.sol";
import { SmartSessionsHarness } from "./utils/SmartSessionsHarness.sol";
import { Roles } from "zodiac-roles/Roles.sol";
import { Enum as ZodiacEnum } from "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IAccount } from "account-abstraction/interfaces/IAccount.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";

/**
 * Gas benchmark - measured, per transaction, including intrinsic gas.
 *
 *   OPERATOR_KEY_GAS=true forge test --mc OperatorKeyGas --isolate     (or: pnpm gas:operator-keys)
 *
 * `--isolate` runs every top-level call as its own transaction (cold storage, 21 000 intrinsic gas,
 * calldata), and `vm.snapshotGasLastCall` records that transaction's gas into snapshots/<group>.json.
 * Without the env flag the tests are SKIPPED, so a normal `forge test` never writes call-frame
 * numbers into the snapshots. Deployment gas comes from the broadcast receipts of
 * script/DeployOperatorKeys.s.sol instead (contract creations are not "calls" here).
 *
 * Both architectures run the same operations, on the same Safe v1.5.0 stack, with and without
 * the Policy Engine installed (the `-without-policy-engine` groups), so its overhead is isolated too.
 * User operations carry zero gas fees, so no prefund is paid in these numbers.
 */
abstract contract OperatorKeyGas is OperatorKeyBase {
    modifier bench() {
        if (!vm.envOr("OPERATOR_KEY_GAS", false)) vm.skip(true);
        _;
    }

    function _group() internal view virtual returns (string memory);

    function _snap(string memory name) internal returns (uint256 gasUsed) {
        gasUsed = vm.snapshotGasLastCall(_group(), name);
        assertGt(gasUsed, 21_000, "not isolated: run with --isolate");
    }

    function _ok(bool ok, bytes memory reason) internal pure {
        if (!ok) _bubble(reason);
    }

    function test_gas_authorizedExecution() public bench {
        (bool ok, bytes memory r) =
            _operatorExec(operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 100e6)), 0));
        _snap("authorizedExecution_first");
        _ok(ok, r);
        (ok, r) =
            _operatorExec(operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (bob, 100e6)), 0));
        _snap("authorizedExecution");
        _ok(ok, r);
    }

    function _batch(uint256 n) internal view returns (Exec[] memory es) {
        es = new Exec[](n);
        for (uint256 i; i < n; i++) {
            es[i] =
                Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (i % 2 == 0 ? alice : bob, 100e6)), 0);
        }
    }

    function test_gas_batchedExecution() public bench {
        (bool ok, bytes memory r) =
            _operatorExec(operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 1e6)), 0));
        _ok(ok, r); // warm-up: same steady state as `authorizedExecution`
        (ok, r) = _operatorBatch(operator, _batch(2));
        _snap("batchedExecution_2");
        _ok(ok, r);
        (ok, r) = _operatorBatch(operator, _batch(5));
        _snap("batchedExecution_5");
        _ok(ok, r);
    }

    function test_gas_operatorRegistration() public bench {
        Exec memory e = _registerOperatorTx(_newKey("next").addr);
        _ownerExecOrFail(e.to, e.value, e.data, e.operation);
        _snap("operatorRegistration");
    }

    function test_gas_operatorRevocation() public bench {
        Exec memory e = _revokeOperatorTx(operator.addr);
        _ownerExecOrFail(e.to, e.value, e.data, e.operation);
        _snap("operatorRevocation");
    }

    function test_gas_operatorRotation() public bench {
        Exec[] memory txs = new Exec[](2);
        txs[0] = _registerOperatorTx(_newKey("next").addr);
        txs[1] = _revokeOperatorTx(operator.addr);
        Exec memory batch = _multiSendExec(txs);
        _ownerExecOrFail(batch.to, 0, batch.data, batch.operation);
        _snap("operatorRotation");
    }
}

contract ZodiacRolesOperatorKeyGasTest is ZodiacRolesHarness, OperatorKeyGas {
    function _group() internal pure override returns (string memory) {
        return "zodiac-roles";
    }

    /// The operator EOA pays and submits itself (no relayer, no signature in calldata).
    function test_gas_authorizedExecution_directEoa() public bench {
        bytes memory d = abi.encodeCall(usdc.transfer, (alice, 1e6));
        vm.prank(operator.addr);
        roles.execTransactionWithRole(address(usdc), 0, d, ZodiacEnum.Operation.Call, ROLE, true);
        d = abi.encodeCall(usdc.transfer, (bob, 100e6));
        vm.prank(operator.addr);
        roles.execTransactionWithRole(address(usdc), 0, d, ZodiacEnum.Operation.Call, ROLE, true);
        _snap("authorizedExecution_directEoa");
    }
}

contract ZodiacRolesOperatorKeyGasWithoutEngineTest is ZodiacRolesHarness, OperatorKeyGas {
    function setUp() public override {
        withoutPolicyEngine = true;
        super.setUp();
    }

    function _group() internal pure override returns (string memory) {
        return "zodiac-roles-without-policy-engine";
    }
}

contract SmartSessionsOperatorKeyGasTest is SmartSessionsHarness, OperatorKeyGas {
    function _group() internal pure override returns (string memory) {
        return "smart-sessions";
    }

    /// With non-zero fees the Safe pays the EntryPoint prefund: one more module tx, policy-checked.
    function test_gas_authorizedExecution_withPrefund() public bench {
        opMaxFee = 1 gwei;
        (bool ok, bytes memory r) =
            _operatorExec(operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 1e6)), 0));
        _ok(ok, r); // warm-up (also pays a prefund)
        (ok, r) =
            _operatorExec(operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (bob, 100e6)), 0));
        _snap("authorizedExecution_withPrefund");
        _ok(ok, r);
    }

    /// Splits the bundler transaction: validation alone, execution alone, and the full handleOps.
    function test_gas_erc4337Decomposition() public bench {
        (bool ok, bytes memory r) =
            _operatorExec(operator, Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 1e6)), 0));
        _ok(ok, r); // warm-up

        bytes memory callData = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(address(usdc), 0, abi.encodeCall(usdc.transfer, (bob, 100e6)))
            )
        );
        PackedUserOperation memory op = _signUserOp(operator, _userOp(callData));
        bytes32 h = entryPoint.getUserOpHash(op);

        uint256 snap = vm.snapshotState();
        vm.prank(ENTRYPOINT_V07);
        IAccount(address(safe)).validateUserOp(op, h, 0);
        _snap("erc4337_validateUserOp_only");
        vm.revertToState(snap);

        snap = vm.snapshotState();
        vm.prank(ENTRYPOINT_V07);
        (ok, r) = address(safe).call(callData);
        _snap("erc4337_execute_only");
        _ok(ok, r);
        vm.revertToState(snap);

        (ok, r) = _submit(op);
        _snap("erc4337_handleOps_total");
        _ok(ok, r);
    }
}

contract SmartSessionsOperatorKeyGasWithoutEngineTest is SmartSessionsHarness, OperatorKeyGas {
    function setUp() public override {
        withoutPolicyEngine = true;
        super.setUp();
    }

    function _group() internal pure override returns (string memory) {
        return "smart-sessions-without-policy-engine";
    }
}
