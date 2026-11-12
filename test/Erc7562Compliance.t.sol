// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { SessionTestBase } from "./utils/SessionTestBase.sol";
import { Erc7562Audit } from "./utils/Erc7562Audit.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { EntryPointSimulations } from "account-abstraction/core/EntryPointSimulations.sol";
import { Session, PermissionId, PolicyData } from "smartsessions/DataTypes.sol";

/**
 * ERC-7562 (validation rules for the ERC-4337 public mempool) - tested, not assumed.
 *
 * Method: run the bundler's standard `EntryPointSimulations.simulateValidation(userOp)` with
 * opcode-level tracing, keep the steps of the account's validation frame, and evaluate them with
 * the rules of Rhinestone's `erc4337-validation` (ERC4337SpecsParser, the checker used by modulekit):
 *   OP-011 banned opcodes, OP-012 GAS, OP-080 BALANCE/SELFBALANCE (staked entities only),
 *   STO-010/021 account and account-associated storage, OP-041 calls to code-less addresses.
 * `_audit` collects EVERY violation (the upstream parser stops at the first one); `_officialVerdict`
 * runs the unmodified upstream Simulator for a pass/fail verdict.
 *
 * This is a rule simulator, not a production bundler; bundlers also differ in which (optional)
 * rules and stake exceptions they apply. Final verification belongs on the target network's bundlers.
 */
contract Erc7562ComplianceTest is SessionTestBase, Erc7562Audit {
    function setUp() public override {
        super.setUp();
        // Same storage, simulation-capable code (what bundlers eth_call with a state override).
        vm.etch(ENTRYPOINT_V07, address(new EntryPointSimulations()).code);
        vm.label(address(safe), "Safe");
        vm.label(address(safe7579), "Safe7579");
        vm.label(address(smartSession), "SmartSession");
        vm.label(address(ownableValidator), "OwnableValidator");
        vm.label(address(timeFramePolicy), "TimeFramePolicy");
        vm.label(address(gasPolicy), "SimpleGasPolicy");
        vm.label(address(gasFeeCapPolicy), "GasFeeCapPolicy");
        vm.label(address(functionPolicy), "FunctionWhitelistPolicy");
        vm.label(address(addressPolicy), "AddressWhitelistPolicy");
        vm.label(address(spendingPolicy), "SpendingLimitPolicy");
        vm.label(address(usdc), "USDC");
        vm.label(ENTRYPOINT_V07, "EntryPoint");
    }

    /*//////////////////////////////////////////////////////////////
                              SCENARIOS
    //////////////////////////////////////////////////////////////*/

    /// Full default session, native transfer.
    function test_7562_defaultSession_eth() public needsTracer {
        PackedUserOperation memory op = _sessionOp(_singleCall(alice, 1 ether, ""));
        string[] memory got = _audit(op, "default session, ETH transfer");
        string[] memory want = new string[](2);
        want[0] = "OP-011 TIMESTAMP in SpendingLimitPolicy";
        want[1] = "OP-080 BALANCE in SpendingLimitPolicy (unstaked)";
        _assertSameSet(got, want);
    }

    function test_7562_defaultSession_upstreamSimulatorRejects() public needsTracer {
        assertFalse(_officialVerdict(_sessionOp(_singleCall(alice, 1 ether, ""))));
    }

    /// Full default session, ERC-20 transfer: balanceOf reads USDC storage associated with the Safe (allowed).
    function test_7562_defaultSession_erc20() public needsTracer {
        PackedUserOperation memory op = _sessionOp(_usdcTransfer(bob, 1000e6));
        string[] memory got = _audit(op, "default session, ERC-20 transfer");
        string[] memory want = new string[](1);
        want[0] = "OP-011 TIMESTAMP in SpendingLimitPolicy";
        _assertSameSet(got, want);
    }

    /// Everything except SpendingLimitPolicy: Safe, Safe7579, SmartSession, OwnableValidator,
    /// TimeFramePolicy, SimpleGasPolicy, GasFeeCapPolicy, FunctionWhitelist, AddressWhitelist.
    function test_7562_withoutSpendingLimit_eth_isCompliant() public needsTracer {
        PermissionId id = _enableSession(_withoutSpendingLimit());
        PackedUserOperation memory op = _signAs(_userOp(_singleCall(alice, 1 ether, "")), sessionKeyPk, id);
        _assertSameSet(_audit(op, "no SpendingLimitPolicy, ETH"), new string[](0));
    }

    function test_7562_withoutSpendingLimit_erc20_isCompliant() public needsTracer {
        PermissionId id = _enableSession(_withoutSpendingLimit());
        PackedUserOperation memory op = _signAs(_userOp(_usdcTransfer(bob, 1000e6)), sessionKeyPk, id);
        _assertSameSet(_audit(op, "no SpendingLimitPolicy, ERC-20"), new string[](0));
    }

    function test_7562_withoutSpendingLimit_upstreamSimulatorAccepts() public needsTracer {
        PermissionId id = _enableSession(_withoutSpendingLimit());
        assertTrue(_officialVerdict(_signAs(_userOp(_singleCall(alice, 1 ether, "")), sessionKeyPk, id)));
    }

    /// SimpleGasPolicy reads BASEFEE only when maxFeePerGas != maxPriorityFeePerGas, which
    /// GasFeeCapPolicy forbids. Shown on a session without GasFeeCapPolicy and with split fees.
    function test_7562_simpleGasPolicyBasefeeOnlyInSplitFeeMode() public needsTracer {
        Session memory s = _withoutSpendingLimit();
        PolicyData[] memory u = new PolicyData[](2);
        u[0] = s.userOpPolicies[0];
        u[1] = s.userOpPolicies[1];
        s.userOpPolicies = u;
        PermissionId id = _enableSession(s);
        PackedUserOperation memory op = _userOp(_singleCall(alice, 1 ether, ""));
        op.gasFees = bytes32(abi.encodePacked(uint128(0), uint128(1)));
        op = _signAs(op, sessionKeyPk, id);
        string[] memory want = new string[](1);
        want[0] = "OP-011 BASEFEE in SimpleGasPolicy";
        _assertSameSet(_audit(op, "no fee cap, split fees"), want);
    }

    /*//////////////////////////////////////////////////////////////
                             THE HARNESS
    //////////////////////////////////////////////////////////////*/

    function _auditAccount() internal view override returns (address) {
        return address(safe);
    }

    function _auditEntryPoint() internal pure override returns (address) {
        return ENTRYPOINT_V07;
    }

    function _withoutSpendingLimit() internal view returns (Session memory s) {
        s = _exchangeSession(sessionKey, bytes32(uint256(7562)), _defaultRecipients());
        PolicyData[] memory a = new PolicyData[](2);
        a[0] = s.actions[0].actionPolicies[0];
        a[1] = s.actions[0].actionPolicies[1];
        s.actions[0].actionPolicies = a;
    }
}
