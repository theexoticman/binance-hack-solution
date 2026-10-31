// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm } from "forge-std/Vm.sol";
import { SessionTestBase } from "./utils/SessionTestBase.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { Session, PermissionId, ConfigId, PolicyData } from "smartsessions/DataTypes.sol";

/**
 * Gas is a second, separate ETH budget: ERC-4337 accounts pay their own gas, and the EntryPoint takes
 * the prefund from the Safe during validation. These tests establish what bounds that outflow.
 *
 * Claim (with SimpleGasPolicy + GasFeeCapPolicy):
 *   ETH that leaves the Safe for gas over a session's configuration lifetime <= gasCostLimit,
 *   whoever bundles, for any gas limits, fees, basefee and number of operations.
 * Reason: GasFeeCapPolicy forces maxFeePerGas == maxPriorityFeePerGas, so the EntryPoint's price is
 *   maxFeePerGas and SimpleGasPolicy counts exactly the prefund; the EntryPoint never charges more
 *   than the prefund (EntryPoint._postExecution) and Safe7579 never sends more than the missing
 *   prefund (Safe7579.validateUserOp).
 */
contract GasAccountingTest is SessionTestBase {
    /// @dev ConfigId of the session's user-op policies (SmartSessions IdLib: permissionId as policy id).
    function _userOpConfigId(PermissionId id) internal view returns (ConfigId) {
        return ConfigId.wrap(keccak256(abi.encodePacked(address(safe), id)));
    }

    function _counted(PermissionId id) internal view returns (uint256 costUsed) {
        (,,, uint128 c) = gasPolicy.getGasConfig(_userOpConfigId(id), address(smartSession), address(safe));
        return c;
    }

    function _op(uint128 verif, uint128 callGas, uint256 pvg, uint128 prio, uint128 maxFee)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _userOp(_singleCall(alice, 1 wei, ""));
        op.accountGasLimits = bytes32(abi.encodePacked(verif, callGas));
        op.preVerificationGas = pvg;
        op.gasFees = bytes32(abi.encodePacked(prio, maxFee));
    }

    /// @dev Session identical to the default one but WITHOUT GasFeeCapPolicy (only expiry + SimpleGasPolicy).
    function _sessionWithoutFeeCap() internal returns (PermissionId id) {
        Session memory s = _exchangeSession(sessionKey, bytes32(uint256(0xFEE)), _defaultRecipients());
        PolicyData[] memory p = new PolicyData[](2);
        p[0] = s.userOpPolicies[0];
        p[1] = s.userOpPolicies[1];
        s.userOpPolicies = p;
        id = _enableSession(s);
    }

    function _charged() internal returns (uint256 actualGasCost) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IEntryPoint.UserOperationEvent.selector) {
                (,, actualGasCost,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
          THE TWO GAPS IN SimpleGasPolicy ALONE (regression evidence)
    //////////////////////////////////////////////////////////////*/

    /// Gap 1: with priority fee 0 the price is 0, so SimpleGasPolicy counts 0 - but the EntryPoint still
    /// takes `limits * maxFeePerGas` from the Safe as prefund and parks the unused part in the deposit.
    function test_gas_gap_prefundParkingWithoutFeeCap() public {
        PermissionId id = _sessionWithoutFeeCap();
        PackedUserOperation memory op =
            _signAs(_op(600_000, 200_000, 50_000, 0, 50_000 gwei), sessionKeyPk, id);
        entryPoint.handleOps(_ops(op), payable(attacker));

        assertEq(_counted(id), 0, "counted nothing");
        assertGt(entryPoint.balanceOf(address(safe)), 40 ether, ">40 ETH of hot-wallet liquidity parked");
        assertLt(address(safe).balance, SAFE_ETH - 40 ether);
    }

    /// Gap 2: in EIP-1559 mode the EntryPoint charges `actualGas * price`, and actualGas includes
    /// EntryPoint overhead that is not inside the gas limits SimpleGasPolicy multiplies.
    function test_gas_gap_undercountWithoutFeeCap() public {
        PermissionId id = _sessionWithoutFeeCap();
        PackedUserOperation memory op = _signAs(
            // Limits just above what validation needs (lower ones fail with AA26).
            _op(190_000, 20_000, 0, 1 gwei, 2 gwei),
            sessionKeyPk,
            id
        );
        vm.recordLogs();
        entryPoint.handleOps(_ops(op), payable(attacker));
        uint256 charged = _charged();
        emit log_named_uint("charged (wei)", charged);
        emit log_named_uint("counted (wei)", _counted(id));
        assertGt(charged, _counted(id), "EntryPoint charged more than the budget counted");
    }

    /*//////////////////////////////////////////////////////////////
                    THE FIX: GasFeeCapPolicy (default session)
    //////////////////////////////////////////////////////////////*/

    function test_gas_fix_rejectsSplitFees() public {
        _assertRejectedInValidation(
            _signAs(_op(600_000, 200_000, 50_000, 0, 50_000 gwei), sessionKeyPk, permissionId),
            _policyViolation(address(gasFeeCapPolicy))
        );
        _assertRejectedInValidation(
            _signAs(_op(240_000, 45_000, 0, 1 gwei, 2 gwei), sessionKeyPk, permissionId),
            _policyViolation(address(gasFeeCapPolicy))
        );
        assertEq(entryPoint.balanceOf(address(safe)), 0);
        assertEq(address(safe).balance, SAFE_ETH);
    }

    function test_gas_fix_rejectsFeeAboveCap() public {
        // Small enough limits that SimpleGasPolicy's budget alone would allow it.
        _assertRejectedInValidation(
            _signAs(
                _op(300_000, 60_000, 0, SESSION_MAX_FEE + 1, SESSION_MAX_FEE + 1), sessionKeyPk, permissionId
            ),
            _policyViolation(address(gasFeeCapPolicy))
        );
    }

    /// With equal fees: counted cost == prefund >= charge, op by op.
    function test_gas_fix_countedEqualsPrefundAndBoundsCharge() public {
        uint128 fee = 10 gwei;
        PackedUserOperation memory op = _signAs(_op(300_000, 20_000, 0, fee, fee), sessionKeyPk, permissionId);
        uint256 prefund = (300_000 + 20_000) * uint256(fee);
        vm.recordLogs();
        entryPoint.handleOps(_ops(op), payable(attacker));
        uint256 charged = _charged();
        assertEq(_counted(permissionId), prefund, "counted == prefund");
        assertLe(charged, prefund, "charge <= prefund (EntryPoint clamps)");
        assertEq(attacker.balance, charged);
    }

    /// Fuzz: repeated operations, arbitrary limits / fees / basefee / fee modes, attacker as bundler.
    function testFuzz_gas_totalOutflowBoundedByBudget(uint256 seed) public {
        for (uint256 i; i < 12; i++) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            uint128 verif = uint128(bound(r, 240_000, 3_000_000));
            uint128 callGas = uint128(bound(r >> 32, 0, 2_000_000));
            uint256 pvg = bound(r >> 64, 0, 3_000_000);
            uint128 maxFee = uint128(bound(r >> 96, 0, 2 * uint256(SESSION_MAX_FEE)));
            // 3 in 4 ops use the permitted equal-fee mode; the rest try a split fee.
            uint128 prio = (r >> 160) % 4 == 0 ? uint128(bound(r >> 168, 0, maxFee)) : maxFee;
            vm.fee(bound(r >> 200, 0, 200 gwei));

            PackedUserOperation memory op =
                _signAs(_op(verif, callGas, pvg, prio, maxFee), sessionKeyPk, permissionId);
            // Rejections are expected (budget, fee cap, gas limits); executions may also revert.
            try entryPoint.handleOps(_ops(op), payable(attacker)) { } catch { }
        }
        // Everything that left the Safe and did not reach alice went to gas.
        uint256 gasOutflow = SAFE_ETH - address(safe).balance - alice.balance;
        assertLe(_counted(permissionId), SESSION_GAS_COST, "counted within budget");
        assertLe(gasOutflow, SESSION_GAS_COST, "Safe ETH spent on gas <= gasCostLimit");
        assertEq(
            gasOutflow, attacker.balance + entryPoint.balanceOf(address(safe)), "outflow = bundler + deposit"
        );
        assertLe(attacker.balance, _counted(permissionId), "bundler never got more than was counted");
    }

    /// Once the budget is exhausted no further op validates, at any fee (including 0 is fine: 0 cost).
    function test_gas_budgetExhaustionStopsPaidOperations() public {
        uint128 fee = SESSION_MAX_FEE;
        // 0.1 ETH / (1.1M gas * 100 gwei) = 0.909 -> the first op of this size already exceeds it.
        PackedUserOperation memory big =
            _signAs(_op(600_000, 400_000, 100_000, fee, fee), sessionKeyPk, permissionId);
        _assertRejectedInValidation(big, _policyViolation(address(gasPolicy)));
        // Smaller ops fit until the budget is used up.
        uint256 ok;
        for (uint256 i; i < 50; i++) {
            PackedUserOperation memory op =
                _signAs(_op(300_000, 60_000, 0, fee, fee), sessionKeyPk, permissionId);
            try entryPoint.handleOps(_ops(op), payable(attacker)) {
                ok++;
            } catch {
                break;
            }
        }
        assertEq(ok, 2, "0.1 ETH / 0.036 ETH per op");
        assertLe(attacker.balance + entryPoint.balanceOf(address(safe)), SESSION_GAS_COST);
    }

    /*//////////////////////////////////////////////////////////////
                    BUDGET SCOPE AND LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /// Budgets are per session: the worst-case gas loss of N compromised sessions is the SUM of budgets.
    function test_gas_budgetsArePerSession() public {
        (address k2, uint256 pk2) = makeAddrAndKey("desk2");
        PermissionId id2 = _enableSession(_exchangeSession(k2, bytes32(uint256(2)), _defaultRecipients()));
        uint128 fee = SESSION_MAX_FEE;
        for (uint256 i; i < 2; i++) {
            _submit(_signAs(_op(300_000, 60_000, 0, fee, fee), sessionKeyPk, permissionId));
            _submit(_signAs(_op(300_000, 60_000, 0, fee, fee), pk2, id2));
        }
        assertEq(_counted(permissionId), 2 * 360_000 * uint256(fee));
        assertEq(_counted(id2), 2 * 360_000 * uint256(fee));
    }

    /// SimpleGasPolicy is a LIFETIME budget and re-initialising it (leadership only) resets usage.
    /// Re-enabling a removed session with the same permissionId also re-initialises it.
    function test_gas_reinitialisationResetsBudget_leadershipOnly() public {
        uint128 fee = SESSION_MAX_FEE;
        _submit(_signAs(_op(300_000, 60_000, 0, fee, fee), sessionKeyPk, permissionId));
        assertGt(_counted(permissionId), 0);

        _execLeadership(
            address(smartSession),
            abi.encodeCall(ISmartSession.removeSession, (permissionId)),
            Enum.Operation.Call
        );
        _enableSession(_exchangeSession(sessionKey, bytes32(0), _defaultRecipients()));
        assertEq(_counted(permissionId), 0, "same permissionId, fresh gas budget");
    }

    /// The Safe's EntryPoint deposit is Safe property; the session cannot withdraw it.
    function test_gas_sessionCannotWithdrawEntryPointDeposit() public {
        vm.deal(address(this), 1 ether);
        entryPoint.depositTo{ value: 1 ether }(address(safe));
        bytes memory withdraw = abi.encodeCall(entryPoint.withdrawTo, (payable(attacker), 1 ether));
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(entryPoint), 0, withdraw)),
            _policyViolation(address(functionPolicy))
        );
        assertEq(entryPoint.balanceOf(address(safe)), 1 ether);

        // Leadership can recover it.
        _execLeadership(address(entryPoint), withdraw, Enum.Operation.Call);
        assertEq(attacker.balance, 1 ether);
    }
}
