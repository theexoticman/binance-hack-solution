// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { VmSafe } from "forge-std/Vm.sol";
import { console2 } from "forge-std/console2.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IEntryPointSimulations } from "account-abstraction/interfaces/IEntryPointSimulations.sol";
import { Simulator } from "erc4337-validation/Simulator.sol";
import { ERC4337SpecsParser } from "erc4337-validation/SpecsParser.sol";

/**
 * @notice ERC-7562 rule audit of an account's validation frame (shared by the ERC-7562 tests).
 *
 * Method: run the bundler's standard `EntryPointSimulations.simulateValidation(userOp)` with
 * opcode-level tracing, keep the steps of the account's validation frame, and evaluate them with
 * the rules of Rhinestone's `erc4337-validation` (ERC4337SpecsParser, the checker used by modulekit):
 *   OP-011 banned opcodes, OP-012 GAS, OP-080 BALANCE/SELFBALANCE (staked entities only),
 *   STO-010/021 account and account-associated storage, OP-041 calls to code-less addresses.
 * `_audit` collects EVERY violation (the upstream parser stops at the first one); `_officialVerdict`
 * runs the unmodified upstream Simulator for a pass/fail verdict.
 *
 * The EntryPoint at `_auditEntryPoint()` must carry `EntryPointSimulations` code.
 */
abstract contract Erc7562Audit is Test {
    string[] internal findings;

    /// @dev Opcode tracing needs forge's tracer (`-vvv`). Without it the tests are reported as SKIPPED.
    ///      Run: `forge test --mc Erc7562ComplianceTest -vvv`
    function probeTracer() external {
        vm.startDebugTraceRecording();
        vm.stopAndReturnDebugTraceRecording();
    }

    modifier needsTracer() {
        try this.probeTracer() { }
        catch {
            vm.skip(true, "needs the tracer: forge test --mc Erc7562ComplianceTest -vvv");
        }
        _;
    }

    function _auditAccount() internal view virtual returns (address);

    function _auditEntryPoint() internal view virtual returns (address);

    function officialVerdictExternal(PackedUserOperation memory op) external returns (bool) {
        return Simulator.simulateUserOp(op, _auditEntryPoint());
    }

    /// @dev Unmodified upstream simulator: true = valid and ERC-7562 compliant.
    function _officialVerdict(PackedUserOperation memory op) internal returns (bool ok) {
        try this.officialVerdictExternal(op) returns (bool valid) {
            ok = valid;
        } catch (bytes memory reason) {
            console2.log("  upstream simulator revert:");
            console2.logBytes(reason);
            ok = false;
        }
    }

    function _audit(PackedUserOperation memory op, string memory title) internal returns (string[] memory) {
        delete findings;
        uint256 snap = vm.snapshotState();
        vm.startMappingRecording();
        vm.startDebugTraceRecording();
        (bool ok,) = _auditEntryPoint().call(abi.encodeCall(IEntryPointSimulations.simulateValidation, (op)));
        VmSafe.DebugStep[] memory steps = vm.stopAndReturnDebugTraceRecording();
        require(ok, "simulateValidation reverted: op is invalid, not just non-compliant");

        VmSafe.DebugStep[] memory v = _accountValidationSteps(steps);
        ERC4337SpecsParser.Entities memory entities;
        entities.account = _auditAccount();
        for (uint256 i; i < v.length; i++) {
            _checkOpcode(v, i);
            _checkStorage(v[i], entities);
            _checkCall(v[i]);
        }
        vm.stopMappingRecording();
        // Copy out before reverting: the snapshot also covers this contract's storage.
        string[] memory result = findings;
        vm.revertToState(snap);

        console2.log(string.concat("[ERC-7562] ", title, ": ", vm.toString(result.length), " violation(s)"));
        for (uint256 i; i < result.length; i++) {
            console2.log(string.concat("    - ", result[i]));
        }
        return result;
    }

    /// Same filter as ERC4337SpecsParser.filterDebugTrace: steps below the EntryPoint while it calls the account.
    function _accountValidationSteps(VmSafe.DebugStep[] memory t)
        internal
        view
        returns (VmSafe.DebugStep[] memory out)
    {
        out = new VmSafe.DebugStep[](t.length);
        uint256 n;
        uint256 startDepth;
        for (uint256 i; i < t.length; i++) {
            if (t[i].contractAddr == _auditEntryPoint()) {
                startDepth = t[i].depth;
                break;
            }
        }
        address current;
        for (uint256 i; i < t.length; i++) {
            if (t[i].depth == startDepth && t[i].contractAddr == _auditEntryPoint()) {
                if (t[i].opcode == 0xF1 || t[i].opcode == 0xFA) current = address(uint160(t[i].stack[1]));
                continue;
            }
            if (t[i].depth > startDepth && current == _auditAccount()) out[n++] = t[i];
        }
        assembly {
            mstore(out, n)
        }
    }

    function _checkOpcode(VmSafe.DebugStep[] memory v, uint256 i) internal {
        uint8 op = v[i].opcode;
        string memory name = _bannedName(op);
        if (bytes(name).length == 0) return;
        if (op == 0x5A) {
            // OP-012: GAS is allowed when immediately followed by a *CALL
            if (i + 1 < v.length) {
                uint8 next = v[i + 1].opcode;
                if (next == 0xF1 || next == 0xF2 || next == 0xF4 || next == 0xFA) return;
            }
            return _add(string.concat("OP-012 GAS not followed by CALL in ", vm.getLabel(v[i].contractAddr)));
        }
        if (op == 0x31 || op == 0x47) {
            return _add(string.concat("OP-080 ", name, " in ", vm.getLabel(v[i].contractAddr), " (unstaked)"));
        }
        _add(string.concat("OP-011 ", name, " in ", vm.getLabel(v[i].contractAddr)));
    }

    function _checkStorage(VmSafe.DebugStep memory s, ERC4337SpecsParser.Entities memory entities) internal {
        if (s.opcode != 0x54 && s.opcode != 0x55 && s.opcode != 0x5C && s.opcode != 0x5D) return;
        if (s.contractAddr == entities.account) return; // STO-010
        bytes32 slot = bytes32(s.stack[0]);
        if (ERC4337SpecsParser.isAssociatedStorage(slot, s.contractAddr, entities.account)) return; // STO-021
        bool write = s.opcode == 0x55 || s.opcode == 0x5D;
        _add(
            string.concat(
                "STO-021 unassociated ", write ? "write" : "read", " in ", vm.getLabel(s.contractAddr)
            )
        );
    }

    function _checkCall(VmSafe.DebugStep memory s) internal {
        if (s.opcode != 0xF1 && s.opcode != 0xF2 && s.opcode != 0xF4 && s.opcode != 0xFA) return;
        address target = address(uint160(s.stack[1]));
        if (
            target.code.length != 0 || target == _auditAccount() || uint160(target) <= 0x09
                || uint160(target) == 0x100
        ) {
            return;
        }
        _add(string.concat("OP-041 call to code-less address from ", vm.getLabel(s.contractAddr)));
    }

    function _bannedName(uint8 op) internal pure returns (string memory) {
        if (op == 0x3A) return "GASPRICE";
        if (op == 0x45) return "GASLIMIT";
        if (op == 0x44) return "PREVRANDAO";
        if (op == 0x42) return "TIMESTAMP";
        if (op == 0x48) return "BASEFEE";
        if (op == 0x4A) return "BLOBBASEFEE";
        if (op == 0x49) return "BLOBHASH";
        if (op == 0x40) return "BLOCKHASH";
        if (op == 0x43) return "NUMBER";
        if (op == 0x47) return "SELFBALANCE";
        if (op == 0x31) return "BALANCE";
        if (op == 0x32) return "ORIGIN";
        if (op == 0x5A) return "GAS";
        if (op == 0xF0) return "CREATE";
        if (op == 0x41) return "COINBASE";
        if (op == 0xFF) return "SELFDESTRUCT";
        return "";
    }

    function _add(string memory f) internal {
        for (uint256 i; i < findings.length; i++) {
            if (keccak256(bytes(findings[i])) == keccak256(bytes(f))) return;
        }
        findings.push(f);
    }

    function _assertSameSet(string[] memory got, string[] memory want) internal pure {
        assertEq(got.length, want.length, "number of distinct violations");
        for (uint256 i; i < want.length; i++) {
            bool found;
            for (uint256 j; j < got.length; j++) {
                if (keccak256(bytes(got[j])) == keccak256(bytes(want[i]))) found = true;
            }
            assertTrue(found, want[i]);
        }
    }
}
