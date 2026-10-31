// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { SessionTestBase } from "./utils/SessionTestBase.sol";
import { AdminSurface } from "./utils/AdminSurface.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Safe7579 } from "safe7579/Safe7579.sol";
import { Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { ValidationData } from "smartsessions/DataTypes.sol";

/**
 * Item 5 - privilege isolation, exhaustively.
 *
 * 1. Sweep: every state-changing function of every deployed contract (66, generated from the
 *    compiled ABIs by script/gen-admin-surface.sh) is attempted by the session through every route:
 *    single `execute`, as an element of a batch that is otherwise valid, and as direct userOp
 *    callData. Each attempt must be rejected by SmartSession validation for a permission-level
 *    reason, and through the real EntryPoint path; afterwards the Safe is unchanged.
 * 2. Property (fuzz): ANY operation that passes validation is a native or ERC-20 transfer to a
 *    whitelisted beneficiary within the per-transaction limit.
 * 3. Inventory: the only non-owner execution path on the account is Safe7579 -> SmartSession.
 */
contract PrivilegeIsolationTest is SessionTestBase {
    bytes4[] internal allowedReasons;
    uint256 internal attempts;

    function setUp() public override {
        super.setUp();
        allowedReasons.push(bytes4(keccak256("PolicyViolation(bytes32,address)")));
        allowedReasons.push(bytes4(keccak256("NoPoliciesSet(bytes32)")));
        allowedReasons.push(bytes4(keccak256("InvalidSelfCall()")));
        allowedReasons.push(bytes4(keccak256("UnsupportedExecutionType()")));
        allowedReasons.push(bytes4(keccak256("UnsupportedCallType(bytes1)")));
    }

    /*//////////////////////////////////////////////////////////////
                                 SWEEP
    //////////////////////////////////////////////////////////////*/

    function test_P_sweepEveryStateChangingFunction() public {
        CriticalConfig memory before = _snapshot();
        _sweep(address(safe), AdminSurface.Safe);
        _sweep(address(safe), AdminSurface.Safe7579); // reached through the Safe's fallback handler
        _sweep(address(safe7579), AdminSurface.Safe7579); // the adapter singleton itself
        _sweep(address(smartSession), AdminSurface.SmartSession);
        _sweep(address(entryPoint), AdminSurface.EntryPoint);
        _sweep(address(ownableValidator), AdminSurface.OwnableValidator);
        _sweep(address(timeFramePolicy), AdminSurface.TimeFramePolicy);
        _sweep(address(gasPolicy), AdminSurface.SimpleGasPolicy);
        _sweep(address(gasFeeCapPolicy), AdminSurface.GasFeeCapPolicy);
        _sweep(address(functionPolicy), AdminSurface.FunctionWhitelistPolicy);
        _sweep(address(addressPolicy), AdminSurface.AddressWhitelistPolicy);
        _sweep(address(spendingPolicy), AdminSurface.SpendingLimitPolicy);
        _sweep(address(usdc), AdminSurface.MockERC20);
        emit log_named_uint("attempts rejected", attempts);
        assertEq(attempts, 3 * (14 + 8 + 8 + 14 + 11 + 5 + 1 + 2 + 1 + 2 + 2 + 2 + 4));
        _assertUnchanged(before);
        assertEq(usdc.allowance(address(safe), sessionKey), 0);
    }

    function _sweep(address target, function() pure returns (bytes4[] memory, string[] memory) list)
        internal
    {
        (bytes4[] memory sels, string[] memory names) = list();
        for (uint256 i; i < sels.length; i++) {
            bytes memory data = abi.encodePacked(sels[i], new bytes(128));
            // Route 1: execute(target, data)
            _expectPermissionRejection(_sessionOp(_singleCall(target, 0, data)), names[i], "single");
            // Route 2: hidden inside an otherwise valid batch
            Execution[] memory execs = new Execution[](2);
            execs[0] = Execution({ target: alice, value: 0.1 ether, callData: "" });
            execs[1] = Execution({ target: target, value: 0, callData: data });
            _expectPermissionRejection(_sessionOp(_batchCall(execs)), names[i], "batch");
            // Route 3: as the userOp's own callData (an account-level call, not `execute`)
            if (sels[i] == Safe7579.execute.selector) {
                attempts++; // the one legitimate entry point - covered by routes 1/2 and every other test
                continue;
            }
            _expectPermissionRejection(_sessionOp(data), names[i], "direct");
        }
    }

    function _expectPermissionRejection(
        PackedUserOperation memory op,
        string memory name,
        string memory route
    ) internal {
        bytes32 h = entryPoint.getUserOpHash(op);
        vm.prank(address(safe));
        try smartSession.validateUserOp(op, h) {
            revert(string.concat("ACCEPTED: ", name, " via ", route));
        } catch (bytes memory reason) {
            bool ok;
            for (uint256 j; j < allowedReasons.length; j++) {
                if (reason.length >= 4 && bytes4(reason) == allowedReasons[j]) ok = true;
            }
            if (!ok) {
                emit log_named_bytes(string.concat("unexpected reason: ", name, " via ", route), reason);
                revert("rejection was not a permission decision");
            }
        }
        _assertRejectedByEntryPointAA23(op);
        attempts++;
    }

    /*//////////////////////////////////////////////////////////////
                         PROPERTY: accepted => allowed
    //////////////////////////////////////////////////////////////*/

    struct FuzzCase {
        address target;
        uint256 value;
        address to;
        uint256 amount;
        bytes data;
    }

    function testFuzz_P_anythingAcceptedIsAnAllowedTransfer(
        uint8 targetIdx,
        uint8 shape,
        uint256 value,
        address to,
        uint256 amount,
        bytes calldata junk,
        bool batch
    ) public {
        FuzzCase memory c = _fuzzCase(targetIdx, shape, value, to, amount, junk);
        PackedUserOperation memory op = _sessionOp(_wrap(c, batch));
        bytes32 h = entryPoint.getUserOpHash(op);
        vm.prank(address(safe));
        try smartSession.validateUserOp(op, h) returns (ValidationData) {
            assertTrue(_isAllowedTransfer(c), "validation accepted a non-allowed operation");
        } catch { }
    }

    function _fuzzCase(
        uint8 targetIdx,
        uint8 shape,
        uint256 value,
        address to,
        uint256 amount,
        bytes calldata junk
    ) internal view returns (FuzzCase memory c) {
        address[13] memory targets = [
            address(safe),
            address(safe7579),
            address(smartSession),
            address(entryPoint),
            address(ownableValidator),
            address(functionPolicy),
            address(addressPolicy),
            address(spendingPolicy),
            address(usdc),
            alice,
            bob,
            attacker,
            sessionKey
        ];
        c.target = targets[targetIdx % targets.length];
        c.to = shape % 2 == 0 ? [alice, bob, attacker, address(safe)][uint8(amount) % 4] : to;
        c.value = bound(value, 0, 2 ether);
        c.amount = bound(amount, 0, 2 * uint256(USDC_PER_TX));
        uint8 s = shape % 5;
        if (s == 1) c.data = abi.encodeCall(usdc.transfer, (c.to, c.amount));
        else if (s == 2) c.data = abi.encodePacked(abi.encodeCall(usdc.transfer, (c.to, c.amount)), junk);
        else if (s == 3) c.data = junk;
        else if (s == 4) c.data = abi.encodeCall(usdc.approve, (c.to, c.amount));
    }

    function _wrap(FuzzCase memory c, bool batch) internal pure returns (bytes memory) {
        if (!batch) return _singleCall(c.target, c.value, c.data);
        Execution[] memory e = new Execution[](1);
        e[0] = Execution({ target: c.target, value: c.value, callData: c.data });
        return _batchCall(e);
    }

    function _isAllowedTransfer(FuzzCase memory c) internal view returns (bool) {
        bool nativeOk = c.data.length == 0 && (c.target == alice || c.target == bob) && c.value <= ETH_PER_TX;
        bool erc20Ok = c.target == address(usdc) && c.value == 0
            && keccak256(c.data) == keccak256(abi.encodeCall(usdc.transfer, (c.to, c.amount)))
            && (c.to == alice || c.to == bob) && c.amount <= USDC_PER_TX;
        return nativeOk || erc20Ok;
    }

    /*//////////////////////////////////////////////////////////////
                              INVENTORY
    //////////////////////////////////////////////////////////////*/

    function test_P_inventoryOfExecutionPaths() public view {
        Safe7579 account = Safe7579(payable(address(safe)));
        (address[] memory modules,) = safe.getModulesPaginated(address(0x1), 100);
        assertEq(modules.length, 1, "one Safe module");
        assertEq(modules[0], address(safe7579));
        assertEq(vm.load(address(safe), GUARD_SLOT), bytes32(0), "no Safe guard");
        (address[] memory validators,) = account.getValidatorsPaginated(address(0x1), 100);
        assertEq(validators.length, 1, "one 7579 validator");
        assertEq(validators[0], address(smartSession));
        (address[] memory executors,) = account.getExecutorsPaginated(address(0x1), 100);
        assertEq(executors.length, 0, "no 7579 executors");
        assertEq(account.getActiveHook(), address(0), "no global hook");
        bytes4[4] memory hooked = [
            Safe7579.execute.selector,
            Safe7579.executeFromExecutor.selector,
            Safe7579.installModule.selector,
            Safe7579.uninstallModule.selector
        ];
        for (uint256 i; i < hooked.length; i++) {
            assertEq(account.getActiveHook(hooked[i]), address(0), "no selector hook");
        }
        // One session, and it cannot sign as the Safe or use a paymaster.
        assertEq(smartSession.getPermissionIDs(address(safe)).length, 1);
        assertEq(smartSession.getERC1271Policies(address(safe), permissionId).length, 0);
    }

    /// Calling the Safe7579 singleton directly only configures the CALLER as an account.
    function test_P_directCallsToAdapterSingletonAffectOnlyTheCaller() public {
        vm.prank(attacker);
        try safe7579.installModule(2, attacker, "") { } catch { }
        assertFalse(Safe7579(payable(address(safe))).isModuleInstalled(2, attacker, ""));
    }

    /// Safe.simulateAndRevert is public and DELEGATECALLs arbitrary code - but always reverts.
    function test_P_simulateAndRevertCannotPersistState() public {
        CriticalConfig memory before = _snapshot();
        vm.prank(attacker);
        (bool ok,) = address(safe)
            .call(
                abi.encodeWithSignature(
                    "simulateAndRevert(address,bytes)",
                    address(this),
                    abi.encodeWithSignature("drainInSafeContext(address)", attacker)
                )
            );
        assertFalse(ok);
        _assertUnchanged(before);
    }

    function drainInSafeContext(address to) external {
        payable(to).transfer(address(this).balance);
    }
}
