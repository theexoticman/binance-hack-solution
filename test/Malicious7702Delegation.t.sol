// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm } from "forge-std/Vm.sol";
import { SessionTestBase } from "./utils/SessionTestBase.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { EncodeLib } from "smartsessions/lib/EncodeLib.sol";
import { PermissionId } from "smartsessions/DataTypes.sol";
import { ConfigId } from "src/interfaces/ISessionPolicy.sol";
import { MaliciousDelegation } from "src/examples/MaliciousDelegation.sol";

/**
 * Test A - the session EOA's private key is fully compromised and the attacker uses a *real*
 * EIP-7702 authorization to point the session EOA at `MaliciousDelegation`.
 *
 * Threat-model reminder: 7702 lets the key holder change the code of THEIR OWN EOA. It does not
 * touch the Safe's code, owners or modules. The question is whether any part of the Safe stack
 * treats "msg.sender == session EOA", "tx.origin", or "the session EOA has code" as extra authority.
 */
contract Malicious7702DelegationTest is SessionTestBase {
    MaliciousDelegation internal maliciousImpl;
    MaliciousDelegation internal hijacked; // == the session EOA, after delegation
    bytes32 internal safeCodeHash;

    function setUp() public override {
        super.setUp();
        maliciousImpl = new MaliciousDelegation();
        hijacked = MaliciousDelegation(payable(sessionKey));
        safeCodeHash = address(safe).codehash;
    }

    /*//////////////////////////////////////////////////////////////
                     THE COMPROMISE (real EIP-7702)
    //////////////////////////////////////////////////////////////*/

    /// @dev Signs and applies an EIP-7702 authorization with the stolen key and proves it took effect.
    function _compromise() internal {
        assertEq(sessionKey.code.length, 0, "session key starts as a plain EOA");

        Vm.SignedDelegation memory auth = vm.signDelegation(address(maliciousImpl), sessionKeyPk);
        // The authorization is a genuine EIP-7702 tuple signed by the session key itself.
        assertEq(_recoverAuthority(auth), sessionKey, "authority must be the session EOA");
        vm.attachDelegation(auth);

        // Delegation designator 0xef0100 || implementation is now the session EOA's code.
        assertEq(
            sessionKey.code, abi.encodePacked(hex"ef0100", address(maliciousImpl)), "delegation not applied"
        );
        // EIP-7702 cannot touch any other account: the Safe's code is unchanged.
        assertEq(address(safe).codehash, safeCodeHash, "safe code changed");
    }

    function test_A_delegationChangesOnlyTheSessionEoa() public {
        // A legitimate operation works before the compromise.
        _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        assertEq(alice.balance, 1 ether);

        CriticalConfig memory before = _snapshot();
        _compromise();
        _assertUnchanged(before);
    }

    /*//////////////////////////////////////////////////////////////
               DIRECT ROUTES FROM THE DELEGATED EOA'S CODE
    //////////////////////////////////////////////////////////////*/

    function test_A_drainAllRoutes_allFail() public {
        _compromise();
        CriticalConfig memory before = _snapshot();

        vm.recordLogs();
        vm.prank(sessionKey, sessionKey); // EOA sends a tx to itself: msg.sender == tx.origin == session EOA
        uint256 successes = hijacked.drainAll(address(safe), address(usdc), attacker);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 attempts;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] != MaliciousDelegation.AttackAttempt.selector) continue;
            assertEq(logs[i].emitter, sessionKey, "attack ran as the session EOA");
            (string memory route, bool ok,) = abi.decode(logs[i].data, (string, bool, bytes));
            assertFalse(ok, route);
            attempts++;
        }
        assertEq(attempts, 9, "all routes attempted");
        assertEq(successes, 0);
        _assertUnchanged(before);
        assertEq(attacker.balance, 0);
        assertEq(usdc.balanceOf(attacker), 0);
    }

    // Each route individually, with the exact revert proving which boundary stopped it.

    function test_A_routeSafeModuleExec_GS104() public {
        _compromise();
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(bytes("GS104")); // Safe: "Method can only be called from an enabled module"
        hijacked.drainViaModule(address(safe), attacker, SAFE_ETH, "");
    }

    function test_A_routeSafeExecTransaction_GS026() public {
        _compromise();
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(bytes("GS026")); // Safe: "Invalid owner provided"
        hijacked.drainViaExecTransaction(address(safe), attacker, SAFE_ETH, "");
    }

    function test_A_routeSafe7579Execute_unauthorized() public {
        _compromise();
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(abi.encodeWithSignature("AccountAccessUnauthorized()"));
        hijacked.drainVia7579Execute(address(safe), attacker, SAFE_ETH, "");
    }

    function test_A_routeSafe7579Executor_notInstalled() public {
        _compromise();
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(abi.encodeWithSignature("InvalidModule(address)", sessionKey));
        hijacked.drainVia7579Executor(address(safe), attacker, SAFE_ETH, "");
    }

    function test_A_routeErc20TransferFrom_noAllowance() public {
        _compromise();
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, sessionKey, 0, SAFE_USDC)
        );
        hijacked.drainViaTransferFrom(address(usdc), address(safe), attacker);
    }

    function test_A_routeAddOwner_GS031() public {
        _compromise();
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(bytes("GS031")); // Safe: "Method can only be called from this contract"
        hijacked.escalateAddOwner(address(safe), attacker);
    }

    function test_A_routeEnableModule_GS031() public {
        _compromise();
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(bytes("GS031"));
        hijacked.escalateEnableModule(address(safe));
    }

    function test_A_routeInstall7579Executor_unauthorized() public {
        _compromise();
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(abi.encodeWithSignature("AccountAccessUnauthorized()"));
        hijacked.escalateInstallExecutor(address(safe));
    }

    function test_A_routeSmartSessionValidateDirectly() public {
        _compromise();
        PackedUserOperation memory op = _sessionOp(_singleCall(attacker, SAFE_ETH, ""));
        bytes32 h = entryPoint.getUserOpHash(op);
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(abi.encodeWithSignature("InvalidUserOpSender(address)", address(safe)));
        smartSession.validateUserOp(op, h);
    }

    /// @dev Writing policy state directly lands in the attacker's own namespace only.
    function test_A_routeOverwritePolicyNamespace() public {
        _compromise();
        address[] memory r = new address[](1);
        r[0] = attacker;
        vm.prank(sessionKey, sessionKey);
        hijacked.overwritePolicy(
            address(addressPolicy), address(safe), ConfigId.unwrap(actionConfigId), abi.encode(r)
        );

        assertTrue(addressPolicy.isWhitelisted(actionConfigId, sessionKey, address(safe), attacker));
        assertFalse(
            addressPolicy.isWhitelisted(actionConfigId, address(smartSession), address(safe), attacker)
        );
        _assertRejectedInValidation(
            _sessionOp(_singleCall(attacker, 1 ether, "")), _policyViolation(address(addressPolicy))
        );
    }

    /*//////////////////////////////////////////////////////////////
                THE REAL SESSION PATH (EntryPoint -> Safe)
    //////////////////////////////////////////////////////////////*/

    /// @dev The compromised key still holds exactly the permissions it was granted - nothing more.
    function test_A_compromisedKeyKeepsOnlyGrantedPermissions() public {
        _compromise();
        CriticalConfig memory before = _snapshot();

        // Out-of-policy: blocked at the policy boundary.
        _assertRejectedInValidation(
            _sessionOp(_singleCall(attacker, 1 ether, "")), _policyViolation(address(addressPolicy))
        );
        _assertRejectedInValidation(
            _sessionOp(_usdcTransfer(attacker, 1e6)), _policyViolation(address(addressPolicy))
        );
        _assertRejectedInValidation(
            _sessionOp(_singleCall(alice, 2 ether, "")), _policyViolation(address(spendingPolicy))
        );
        // Gas-fee extraction through an attacker-run bundler: capped by SimpleGasPolicy.
        PackedUserOperation memory feeOp = _userOp(_singleCall(alice, 1 wei, ""));
        feeOp.preVerificationGas = 4_000_000;
        feeOp.gasFees = bytes32(abi.encodePacked(uint128(10_000 gwei), uint128(10_000 gwei)));
        _assertRejectedInValidation(
            _signAs(feeOp, sessionKeyPk, permissionId), _policyViolation(address(gasPolicy))
        );
        _assertUnchanged(before);

        // In-policy: still possible (EXPECTED - this is the residual risk of a compromised key).
        // Worst case for one day: the whole remaining budget, and only to whitelisted destinations.
        for (uint256 i; i < 5; i++) {
            _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        }
        for (uint256 i; i < 3; i++) {
            _submit(_sessionOp(_usdcTransfer(bob, 1000e6)));
        }
        _assertRejectedInValidation(
            _sessionOp(_singleCall(alice, 1 wei, "")), _policyViolation(address(spendingPolicy))
        );
        _assertRejectedInValidation(
            _sessionOp(_usdcTransfer(bob, 1)), _policyViolation(address(spendingPolicy))
        );

        assertEq(address(safe).balance, SAFE_ETH - ETH_PER_DAY, "max ETH loss == daily budget");
        assertEq(usdc.balanceOf(address(safe)), SAFE_USDC - USDC_PER_DAY, "max USDC loss == daily budget");
        assertEq(attacker.balance + usdc.balanceOf(attacker), 0, "nothing reached the attacker");
    }

    /// @dev The delegated EOA acts as bundler (msg.sender == tx.origin == EOA with code).
    ///      Neither SmartSession nor the policies look at msg.sender / tx.origin.
    function test_A_delegatedEoaAsBundler() public {
        _compromise();
        // Build (and sign) ops before pranking: building them makes external calls.
        PackedUserOperation[] memory attack = _ops(_sessionOp(_singleCall(attacker, 1 ether, "")));
        vm.prank(sessionKey, sessionKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("ExecutionFailed()")
            )
        );
        hijacked.bundle(entryPoint, attack);

        PackedUserOperation[] memory legit = _ops(_sessionOp(_singleCall(alice, 1 ether, "")));
        vm.prank(sessionKey, sessionKey);
        hijacked.bundle(entryPoint, legit);
        assertEq(alice.balance, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
       INVESTIGATION: the session validator's "signer has no code" assumption
    //////////////////////////////////////////////////////////////*/

    /**
     * Rhinestone's OwnableValidator (via CheckNSignatures) accepts Safe-style contract signatures
     * (`v == 0`, signer in `r`), verified with ERC-1271 on the signer. A plain EOA has no code, so
     * this path is dead. After a 7702 delegation the session EOA HAS code and its
     * `isValidSignature` is attacker-defined: anyone can now produce "signatures" for the session.
     *
     * This does not add authority - the policies still bound every operation - but it means
     * the stolen key is no longer needed to use the session (e.g. after the attacker discards
     * it), so revocation is the only remedy. See docs/THREAT_MODEL.md.
     */
    function test_A_erc1271SignerHijack_anyoneCanDriveSession_withinPolicyOnly() public {
        PackedUserOperation memory op = _userOp(_singleCall(alice, 1 ether, ""));
        op.signature = _contractSignature(sessionKey, permissionId);

        // Before 7702: the session EOA has no code, contract signatures cannot verify.
        bytes32 h = entryPoint.getUserOpHash(op);
        vm.prank(address(safe));
        vm.expectRevert(); // call to a code-less address: abi decoding of empty returndata fails
        smartSession.validateUserOp(op, h);
        _assertRejectedByEntryPointAA23(op);

        _compromise();

        // After 7702: a third party with NO key submits an in-policy op - accepted.
        address thirdParty = makeAddr("thirdParty");
        vm.prank(thirdParty, thirdParty);
        entryPoint.handleOps(_ops(op), payable(thirdParty));
        assertEq(alice.balance, 1 ether);

        // ...but out-of-policy ops are still blocked at the policy boundary.
        PackedUserOperation memory bad = _userOp(_singleCall(attacker, 1 ether, ""));
        bad.signature = _contractSignature(sessionKey, permissionId);
        _assertRejectedInValidation(bad, _policyViolation(address(addressPolicy)));
    }

    /*//////////////////////////////////////////////////////////////
               SESSION IDENTITY / PERMISSION-CONTEXT SWITCHING
    //////////////////////////////////////////////////////////////*/

    function test_A_cannotSwitchToAnotherSessionsPermissions() public {
        // A second desk with a different signer and a different whitelist.
        (address desk2, uint256 desk2Pk) = makeAddrAndKey("desk2SessionKey");
        address carol = makeAddr("carol");
        address[] memory r = new address[](1);
        r[0] = carol;
        PermissionId id2 = _enableSession(_exchangeSession(desk2, bytes32(uint256(2)), r));

        _compromise();

        // (a) stolen key ECDSA-signs under desk2's permissionId -> signer mismatch
        _assertRejectedByEntryPoint(
            _signAs(_userOp(_singleCall(carol, 1 ether, "")), sessionKeyPk, id2), "AA24 signature error"
        );

        // (b) hijacked ERC-1271 signer claims desk2's permission -> not an owner of that session
        PackedUserOperation memory op = _userOp(_singleCall(carol, 1 ether, ""));
        op.signature = _contractSignature(sessionKey, id2);
        _assertRejectedByEntryPoint(op, "AA24 signature error");

        // (c) contract signature naming desk2's EOA (no code) as signer -> cannot verify
        op.signature = _contractSignature(desk2, id2);
        _assertRejectedByEntryPointAA23(op);

        // (d) desk2's own key still works: the attack did not disturb other sessions.
        _submit(_signAs(_userOp(_singleCall(carol, 1 ether, "")), desk2Pk, id2));
        assertEq(carol.balance, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    PRIVILEGE ESCALATION FROM 7702 STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Test B, repeated with the delegated EOA driving real userOps.
    function test_A_escalationAttemptsAfterDelegation() public {
        _compromise();
        CriticalConfig memory before = _snapshot();

        bytes[4] memory selfCalls = [
            abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", attacker, 1),
            abi.encodeWithSignature("changeThreshold(uint256)", 1),
            abi.encodeWithSignature("enableModule(address)", sessionKey),
            abi.encodeWithSignature("setGuard(address)", address(0))
        ];
        for (uint256 i; i < selfCalls.length; i++) {
            _assertRejectedInValidation(
                _sessionOp(_singleCall(address(safe), 0, selfCalls[i])),
                _policyViolation(address(functionPolicy))
            );
        }
        _assertRejectedInValidation(
            _sessionOp(abi.encodeWithSignature("installModule(uint256,address,bytes)", 2, sessionKey, "")),
            abi.encodeWithSignature("NoPoliciesSet(bytes32)", permissionId)
        );
        _assertUnchanged(before);
    }

    /// @dev The attacker can re-delegate at will; nothing about the Safe changes.
    function test_A_redelegationIsIrrelevantToTheSafe() public {
        _compromise();
        CriticalConfig memory before = _snapshot();

        MaliciousDelegation impl2 = new MaliciousDelegation();
        vm.signAndAttachDelegation(address(impl2), sessionKeyPk);
        assertEq(sessionKey.code, abi.encodePacked(hex"ef0100", address(impl2)));

        vm.prank(sessionKey, sessionKey);
        assertEq(hijacked.drainAll(address(safe), address(usdc), attacker), 0);
        _assertUnchanged(before);
        assertEq(address(safe).codehash, safeCodeHash);
    }

    /*//////////////////////////////////////////////////////////////
                         INCIDENT RESPONSE
    //////////////////////////////////////////////////////////////*/

    function test_A_leadershipRevocationEndsTheCompromise() public {
        _compromise();
        _execLeadership(
            address(smartSession),
            abi.encodeWithSignature("removeSession(bytes32)", permissionId),
            Enum.Operation.Call
        );

        bytes memory revoked = abi.encodeWithSignature("InvalidPermissionId(bytes32)", permissionId);
        _assertRejectedInValidation(_sessionOp(_singleCall(alice, 1 ether, "")), revoked);

        PackedUserOperation memory op = _userOp(_singleCall(alice, 1 ether, ""));
        op.signature = _contractSignature(sessionKey, permissionId);
        _assertRejectedInValidation(op, revoked);
        assertEq(alice.balance, 0);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev SmartSession USE-mode signature carrying a CheckNSignatures contract signature (v == 0):
    ///      r = signer, s = offset of the (empty) ERC-1271 signature blob, v = 0.
    function _contractSignature(address signer, PermissionId id) internal pure returns (bytes memory) {
        return EncodeLib.encodeUse(
            id,
            abi.encodePacked(bytes32(uint256(uint160(signer))), bytes32(uint256(65)), uint8(0), uint256(0))
        );
    }

    /// @dev authority = ecrecover(keccak256(0x05 || rlp([chain_id, address, nonce])), y_parity, r, s)
    function _recoverAuthority(Vm.SignedDelegation memory a) internal view returns (address) {
        bytes memory payload =
            abi.encodePacked(_rlpUint(block.chainid), bytes1(0x94), a.implementation, _rlpUint(a.nonce));
        require(payload.length < 56, "rlp: long list");
        bytes32 digest = keccak256(abi.encodePacked(hex"05", uint8(0xc0 + payload.length), payload));
        return ecrecover(digest, a.v + 27, a.r, a.s);
    }

    function _rlpUint(uint256 x) internal pure returns (bytes memory) {
        if (x == 0) return hex"80";
        if (x < 0x80) return abi.encodePacked(uint8(x));
        uint256 len;
        for (uint256 t = x; t != 0; t >>= 8) {
            len++;
        }
        bytes memory b = new bytes(len);
        for (uint256 i; i < len; i++) {
            b[len - 1 - i] = bytes1(uint8(x >> (8 * i)));
        }
        return abi.encodePacked(uint8(0x80 + len), b);
    }
}
