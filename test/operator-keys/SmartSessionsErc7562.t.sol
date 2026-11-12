// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { SmartSessionsHarness } from "./utils/SmartSessionsHarness.sol";
import { Erc7562Audit } from "../utils/Erc7562Audit.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { EntryPointSimulations } from "account-abstraction/core/EntryPointSimulations.sol";
import { Session, PolicyData } from "smartsessions/DataTypes.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";

/**
 * ERC-7562 with Safe Policy Engine as module guard (Architecture B).
 *
 * Safe7579 runs the validator as a Safe MODULE TRANSACTION, so the module guard - the policy
 * engine - executes inside the ERC-4337 validation frame. This measures what that does to
 * public-mempool compliance. The session used drops SpendingLimitPolicy, which is the
 * configuration test/Erc7562Compliance.t.sol proves compliant without the engine (Safe 1.4.1, no
 * guard), so every violation reported here is introduced by the guard path.
 *
 * Needs forge's tracer: `forge test --mc Erc7562 -vvv` (skipped otherwise, like the existing suite).
 */
contract SmartSessionsPolicyEngineErc7562Test is SmartSessionsHarness, Erc7562Audit {
    function setUp() public override {
        super.setUp();
        vm.etch(ENTRYPOINT_V07, address(new EntryPointSimulations()).code);
        vm.label(address(safe), "Safe");
        vm.label(address(safe7579), "Safe7579");
        vm.label(address(smartSession), "SmartSession");
        vm.label(address(guard), "SafePolicyGuard");
        vm.label(allowedModulePolicy, "AllowedModulePolicy");
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

    function _auditAccount() internal view override returns (address) {
        return address(safe);
    }

    function _auditEntryPoint() internal pure override returns (address) {
        return ENTRYPOINT_V07;
    }

    function _enableWithoutSpendingLimit(Key memory k) internal {
        Session memory s = _session(k.addr);
        PolicyData[] memory a = new PolicyData[](2);
        a[0] = s.actions[0].actionPolicies[0];
        a[1] = s.actions[0].actionPolicies[1];
        s.actions[0].actionPolicies = a;
        s.salt = keccak256("no-spending-limit");
        Session[] memory list = new Session[](1);
        list[0] = s;
        _ownerExecOrFail(address(smartSession), 0, abi.encodeCall(ISmartSession.enableSessions, (list)), 0);
        permissionOf[k.addr] = smartSession.getPermissionId(s);
    }

    function _transferOp(Key memory k) internal view returns (PackedUserOperation memory) {
        return _signUserOp(k, _userOp(_singleCallData(_transfer7562(alice, 1e6))));
    }

    function _transfer7562(address to, uint256 amount) internal view returns (Exec memory) {
        return Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (to, amount)), 0);
    }

    function test_7562_policyEngineInValidation_violations() public needsTracer {
        Key memory k = _newKey("7562");
        _enableWithoutSpendingLimit(k);
        string[] memory got =
            _audit(_transferOp(k), "Safe 1.5.0 + Policy Engine module guard, no SpendingLimitPolicy");
        // SafePolicyGuard writes `$checkingSafe` / `$checkingModule` (fixed slots) on every check and
        // reads guard state not keyed by the account first; AllowedModulePolicy keys its state
        // `[guard][safe][module]`. None of it is account-associated storage under STO-021.
        string[] memory want = new string[](3);
        want[0] = "STO-021 unassociated read in SafePolicyGuard";
        want[1] = "STO-021 unassociated write in SafePolicyGuard";
        want[2] = "STO-021 unassociated read in AllowedModulePolicy";
        _assertSameSet(got, want);
    }

    function test_7562_policyEngineInValidation_upstreamSimulatorRejects() public needsTracer {
        Key memory k = _newKey("7562");
        _enableWithoutSpendingLimit(k);
        assertFalse(_officialVerdict(_transferOp(k)));
    }
}
