// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm } from "forge-std/Vm.sol";
import { SessionTestBase } from "./utils/SessionTestBase.sol";
import { RevertingReceiver } from "./utils/Fixtures.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { EncodeLib } from "smartsessions/lib/EncodeLib.sol";
import { PermissionId, FALLBACK_ACTIONID } from "smartsessions/DataTypes.sol";
import { ConfigId } from "src/interfaces/ISessionPolicy.sol";
import { MaliciousDelegation } from "src/examples/MaliciousDelegation.sol";

/**
 * Item: can failed operations exhaust ANOTHER session's spending allowance?
 *
 * Model: usage is recorded in validation, under ConfigId = f(account, permissionId, action). One
 * session can therefore never write another session's counters. The only shared resource is the
 * Safe's balance: if two sessions' operations are validated in the SAME bundle, the first one's
 * execution can leave too little for the second, whose execution then reverts after its usage was
 * recorded.
 */
contract AccountingIsolationTest is SessionTestBase {
    address internal desk2;
    uint256 internal desk2Pk;
    PermissionId internal id2;
    ConfigId internal cfg2;
    RevertingReceiver internal bad;

    function setUp() public override {
        super.setUp();
        bad = new RevertingReceiver();
        address[] memory r = new address[](3);
        r[0] = alice;
        r[1] = bob;
        r[2] = address(bad);
        _reconfigure(address(addressPolicy), abi.encode(r)); // session A may (mistakenly) pay `bad`
        (desk2, desk2Pk) = makeAddrAndKey("desk2");
        id2 = _enableSession(_exchangeSession(desk2, bytes32(uint256(2)), _defaultRecipients()));
        cfg2 = ConfigId.wrap(
            keccak256(abi.encodePacked(address(safe), keccak256(abi.encodePacked(id2, FALLBACK_ACTIONID))))
        );
    }

    function _spent(ConfigId id, address asset) internal view returns (uint256) {
        return spendingPolicy.spentInCurrentWindow(id, address(smartSession), address(safe), asset);
    }

    /// Session A burns its entire daily ETH budget on executions that revert. Session B is unaffected.
    function test_I_failedOpsOnlyConsumeTheirOwnSession() public {
        for (uint256 i; i < 5; i++) {
            _submit(_sessionOp(_singleCall(address(bad), 1 ether, "")));
        }
        assertEq(_spent(actionConfigId, address(0)), ETH_PER_DAY, "A exhausted (over-count, fail-safe)");
        assertEq(address(safe).balance, SAFE_ETH, "nothing moved");
        assertEq(_spent(cfg2, address(0)), 0, "B untouched");

        for (uint256 i; i < 5; i++) {
            _submit(_signAs(_userOp(_singleCall(alice, 1 ether, "")), desk2Pk, id2));
        }
        assertEq(alice.balance, ETH_PER_DAY, "B spends its full budget");
    }

    /// After a 7702 hijack, a key-less third party can burn A's budget via reverting executions -
    /// still only A's (griefing of the compromised session itself).
    function test_I_hijackedSessionGriefingStaysInsideThatSession() public {
        vm.signAndAttachDelegation(address(new MaliciousDelegation()), sessionKeyPk);
        for (uint256 i; i < 5; i++) {
            PackedUserOperation memory op = _userOp(_singleCall(address(bad), 1 ether, ""));
            op.signature = EncodeLib.encodeUse(
                permissionId,
                abi.encodePacked(
                    bytes32(uint256(uint160(sessionKey))), bytes32(uint256(65)), uint8(0), uint256(0)
                )
            );
            vm.prank(makeAddr("thirdParty"));
            entryPoint.handleOps(_ops(op), payable(makeAddr("thirdParty")));
        }
        assertEq(_spent(actionConfigId, address(0)), ETH_PER_DAY);
        assertEq(_spent(cfg2, address(0)), 0);
    }

    /// The one cross-session effect: balance contention inside ONE bundle. Both ops validate against
    /// the pre-execution balance; A executes first and B's transfer then reverts, after B's usage was
    /// recorded. B over-counts by its own transfer amount; nothing moves that B did not authorise.
    function test_I_sameBundleBalanceContentionOverCountsOtherSession() public {
        // Leave the Safe with 1,500 USDC.
        _execLeadership(
            address(usdc),
            abi.encodeCall(usdc.transfer, (makeAddr("cold"), SAFE_USDC - 1500e6)),
            Enum.Operation.Call
        );
        PackedUserOperation memory a = _sessionOp(_usdcTransfer(alice, 1000e6));
        PackedUserOperation memory b = _signAs(_userOp(_usdcTransfer(bob, 1000e6)), desk2Pk, id2);
        b.nonce = a.nonce + 1; // shared nonce key: the bundle orders them
        b = _signAs(b, desk2Pk, id2);

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = a;
        ops[1] = b;
        entryPoint.handleOps(ops, bundler);

        assertEq(usdc.balanceOf(alice), 1000e6);
        assertEq(usdc.balanceOf(bob), 0, "B's execution reverted");
        assertEq(_spent(cfg2, address(usdc)), 1000e6, "B's budget still charged");
    }

    /// Mitigation available to the operator (no code change): submit each session's operations in
    /// their own handleOps call. B is then validated against the real balance and rejected
    /// without being charged.
    function test_I_separateBundlesRemoveContention() public {
        _execLeadership(
            address(usdc),
            abi.encodeCall(usdc.transfer, (makeAddr("cold"), SAFE_USDC - 1500e6)),
            Enum.Operation.Call
        );
        _submit(_sessionOp(_usdcTransfer(alice, 1000e6)));
        _assertRejectedInValidation(
            _signAs(_userOp(_usdcTransfer(bob, 1000e6)), desk2Pk, id2),
            abi.encodeWithSignature("PolicyViolation(bytes32,address)", id2, address(spendingPolicy))
        );
        assertEq(_spent(cfg2, address(usdc)), 0, "B not charged");
    }
}
