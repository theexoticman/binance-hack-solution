// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { SessionTestBase, ISafeAdmin } from "./utils/SessionTestBase.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { Safe7579 } from "safe7579/Safe7579.sol";
import { ISafe7579 } from "safe7579/ISafe7579.sol";
import { Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { Session, PermissionId } from "smartsessions/DataTypes.sol";
import { SpendingLimitPolicy } from "src/policies/SpendingLimitPolicy.sol";

/**
 * Test D - valid exchange operations keep working.
 * Test E - root (leadership multisig) versus session authority.
 */
contract SessionExecutionTest is SessionTestBase {
    /*//////////////////////////////////////////////////////////////
                         AUTHORITY LAYOUT
    //////////////////////////////////////////////////////////////*/

    function test_setup_authorityLayout() public view {
        // Root authority: 3-of-5 leadership, session key is NOT an owner.
        assertEq(safe.getOwners().length, OWNER_COUNT);
        assertEq(safe.getThreshold(), THRESHOLD);
        assertFalse(safe.isOwner(sessionKey));

        // Exactly one Safe module: the Safe7579 adapter. No other execution path exists.
        (address[] memory modules,) = safe.getModulesPaginated(address(0x1), 10);
        assertEq(modules.length, 1);
        assertEq(modules[0], address(safe7579));
        assertEq(vm.load(address(safe), GUARD_SLOT), bytes32(0));
        assertEq(address(uint160(uint256(vm.load(address(safe), FALLBACK_SLOT)))), address(safe7579));

        // Inside Safe7579: SmartSession is the only validator; no executors; no hooks.
        Safe7579 account = Safe7579(payable(address(safe)));
        (address[] memory validators,) = account.getValidatorsPaginated(address(0x1), 10);
        assertEq(validators.length, 1);
        assertEq(validators[0], address(smartSession));
        (address[] memory executors,) = account.getExecutorsPaginated(address(0x1), 10);
        assertEq(executors.length, 0);
        assertEq(account.getActiveHook(), address(0));

        // The session exists, with exactly one route (catch-all) guarded by three policies.
        assertTrue(smartSession.isPermissionEnabled(permissionId, address(safe)));
        assertEq(smartSession.getEnabledActions(address(safe), permissionId).length, 1);
        assertTrue(functionPolicy.isInitialized(actionConfigId, address(smartSession), address(safe)));
        assertTrue(addressPolicy.isWhitelisted(actionConfigId, address(smartSession), address(safe), alice));
        assertFalse(
            addressPolicy.isWhitelisted(actionConfigId, address(smartSession), address(safe), attacker)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       TEST D: VALID OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_D_whitelistedEthTransferWithinLimits() public {
        _submit(_sessionOp(_singleCall(alice, 1 ether, "")));

        assertEq(alice.balance, 1 ether);
        assertEq(address(safe).balance, SAFE_ETH - 1 ether);
        assertEq(
            spendingPolicy.spentInCurrentWindow(
                actionConfigId, address(smartSession), address(safe), address(0)
            ),
            1 ether
        );
    }

    function test_D_whitelistedErc20TransferWithinLimits() public {
        _submit(_sessionOp(_usdcTransfer(bob, 1000e6)));

        assertEq(usdc.balanceOf(bob), 1000e6);
        assertEq(usdc.balanceOf(address(safe)), SAFE_USDC - 1000e6);
        assertEq(
            spendingPolicy.spentInCurrentWindow(
                actionConfigId, address(smartSession), address(safe), address(usdc)
            ),
            1000e6
        );
    }

    function test_D_multipleTransfersUpToAggregateBudget() public {
        // 5 x 1 ETH == the full 5 ETH daily budget, across separate userOps.
        for (uint256 i; i < 5; i++) {
            _submit(_sessionOp(_singleCall(i % 2 == 0 ? alice : bob, 1 ether, "")));
        }
        assertEq(alice.balance + bob.balance, 5 ether);

        // 3 x 1000 USDC == the full 3000 USDC daily budget. Budgets are per asset.
        for (uint256 i; i < 3; i++) {
            _submit(_sessionOp(_usdcTransfer(alice, 1000e6)));
        }
        assertEq(usdc.balanceOf(alice), 3000e6);
    }

    function test_D_batchOfValidTransfers() public {
        Execution[] memory execs = new Execution[](3);
        execs[0] = Execution({ target: alice, value: 1 ether, callData: "" });
        execs[1] = Execution({ target: bob, value: 0.5 ether, callData: "" });
        execs[2] = Execution({
            target: address(usdc), value: 0, callData: abi.encodeCall(usdc.transfer, (bob, 500e6))
        });

        _submit(_sessionOp(_batchCall(execs)));

        assertEq(alice.balance, 1 ether);
        assertEq(bob.balance, 0.5 ether);
        assertEq(usdc.balanceOf(bob), 500e6);
        assertEq(
            spendingPolicy.spentInCurrentWindow(
                actionConfigId, address(smartSession), address(safe), address(0)
            ),
            1.5 ether
        );
    }

    function test_D_budgetRollsOverAfterPeriod() public {
        for (uint256 i; i < 5; i++) {
            _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        }
        // Exhausted for today (see PolicyEnforcement for the blocked case); next UTC day it resets.
        vm.warp(block.timestamp - (block.timestamp % 1 days) + 1 days);
        _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        assertEq(alice.balance, 6 ether);
    }

    /*//////////////////////////////////////////////////////////////
               TEST D/E: LEADERSHIP-CONTROLLED LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_D_leadershipCreatesAndRevokesSession() public {
        (address desk2, uint256 desk2Pk) = makeAddrAndKey("desk2SessionKey");
        Session memory s2 = _exchangeSession(desk2, bytes32(uint256(2)), _defaultRecipients());
        PermissionId id2 = _enableSession(s2);
        assertTrue(PermissionId.unwrap(id2) != PermissionId.unwrap(permissionId));

        // New session works.
        _submit(_signAs(_userOp(_singleCall(bob, 1 ether, "")), desk2Pk, id2));
        assertEq(bob.balance, 1 ether);

        // Leadership revokes the original session...
        _execLeadership(
            address(smartSession),
            abi.encodeCall(ISmartSession.removeSession, (permissionId)),
            Enum.Operation.Call
        );
        assertFalse(smartSession.isPermissionEnabled(permissionId, address(safe)));

        // ...after which its key is useless,
        _assertRejectedInValidation(
            _sessionOp(_singleCall(alice, 1 ether, "")),
            abi.encodeWithSignature("InvalidPermissionId(bytes32)", permissionId)
        );
        // while the other session is unaffected.
        _submit(_signAs(_userOp(_singleCall(bob, 1 ether, "")), desk2Pk, id2));
        assertEq(bob.balance, 2 ether);
    }

    function test_D_leadershipUpdatesWhitelist() public {
        address carol = makeAddr("carol");
        address[] memory newList = new address[](1);
        newList[0] = carol;

        _reconfigure(address(addressPolicy), abi.encode(newList));

        // Replaced, not appended: alice is gone, carol is in.
        _assertRejectedInValidation(
            _sessionOp(_singleCall(alice, 1 ether, "")), _policyViolation(address(addressPolicy))
        );
        _submit(_sessionOp(_singleCall(carol, 1 ether, "")));
        assertEq(carol.balance, 1 ether);
    }

    function test_D_leadershipRaisesLimit_neverRefundsSpentBudget() public {
        for (uint256 i; i < 5; i++) {
            _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        }

        SpendingLimitPolicy.AssetLimit[] memory l = new SpendingLimitPolicy.AssetLimit[](1);
        l[0] = SpendingLimitPolicy.AssetLimit({
            asset: address(0), maxPerTx: 2 ether, maxPerPeriod: 8 ether, period: 1 days
        });
        _reconfigure(address(spendingPolicy), abi.encode(l));

        // 5 ETH already spent today stays counted: only 3 ETH of new headroom.
        _submit(_sessionOp(_singleCall(alice, 2 ether, "")));
        _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        _assertRejectedInValidation(
            _sessionOp(_singleCall(alice, 1 wei, "")), _policyViolation(address(spendingPolicy))
        );
        assertEq(alice.balance, 8 ether);

        // USDC limit was not part of the new config -> USDC transfers are now rejected (fail-closed).
        _assertRejectedInValidation(
            _sessionOp(_usdcTransfer(alice, 1e6)), _policyViolation(address(spendingPolicy))
        );
    }

    /*//////////////////////////////////////////////////////////////
                  TEST E: ROOT VERSUS SESSION AUTHORITY
    //////////////////////////////////////////////////////////////*/

    function test_E_leadershipAddsOwner_sessionCannot() public {
        address newLeader = makeAddr("newLeader");
        bytes memory addOwner = abi.encodeCall(ISafeAdmin.addOwnerWithThreshold, (newLeader, THRESHOLD));

        // Session key: blocked.
        CriticalConfig memory before = _snapshot();
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(safe), 0, addOwner)), _policyViolation(address(functionPolicy))
        );
        _assertUnchanged(before);

        // Leadership quorum: allowed.
        _execLeadership(address(safe), addOwner, Enum.Operation.Call);
        assertTrue(safe.isOwner(newLeader));
        assertEq(safe.getOwners().length, OWNER_COUNT + 1);
    }

    function test_E_leadershipMovesFundsBeyondSessionLimits() public {
        // Root authority is not bound by session policies: 50 ETH to a non-whitelisted cold wallet.
        address coldWallet = makeAddr("coldWallet");
        _execLeadership(coldWallet, 50 ether, "", Enum.Operation.Call);
        assertEq(coldWallet.balance, 50 ether);

        // The same transfer by the session key passes FunctionWhitelist (native transfers are an
        // allowed operation) and is rejected by AddressWhitelist (beneficiary not whitelisted).
        _assertRejectedInValidation(
            _sessionOp(_singleCall(coldWallet, 1 ether, "")), _policyViolation(address(addressPolicy))
        );
    }

    /// @dev Emergency switch: uninstalling SmartSession wipes every session at once. With no 7579
    ///      validator selected, Safe7579 falls back to the owners' multisig check, which a session
    ///      signature can never pass.
    function test_E_emergencyUninstallKillsAllSessions() public {
        _execLeadership(
            address(safe),
            abi.encodeCall(
                ISafe7579.uninstallModule, (1, address(smartSession), abi.encode(address(0x1), ""))
            ),
            Enum.Operation.Call
        );
        assertFalse(Safe7579(payable(address(safe))).isModuleInstalled(1, address(smartSession), ""));
        assertFalse(smartSession.isPermissionEnabled(permissionId, address(safe)));
        _assertRejectedByEntryPoint(_sessionOp(_singleCall(alice, 1 ether, "")), "AA24 signature error");
    }

    function test_E_belowThresholdLeadershipCannotAct() public {
        bytes memory data = abi.encodeCall(ISafeAdmin.changeThreshold, (1));
        bytes memory twoSigs = _leadershipSignatures(safe, address(safe), 0, data, Enum.Operation.Call, 2);
        vm.expectRevert(bytes("GS020"));
        _execWithSignatures(address(safe), 0, data, Enum.Operation.Call, twoSigs);
    }
}
