// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { SessionTestBase } from "./utils/SessionTestBase.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { EncodeLib } from "smartsessions/lib/EncodeLib.sol";
import { PermissionId } from "smartsessions/DataTypes.sol";
import { MaliciousDelegation } from "src/examples/MaliciousDelegation.sol";

/**
 * Revocation must not depend on the compromised signer, and nothing signed before revocation may
 * execute after it.
 *
 * Signature path (pinned sources): SmartSession -> SignerLib.isValidISessionValidator ->
 * OwnableValidator.validateSignatureWithData (L316) -> CheckSignatures.recoverNSignatures (L339):
 *   v == 0  -> signer = r, ISignatureValidator(signer).isValidSignature(hash, data) (CheckNSignatures L49-L91)
 *   v > 30  -> ECDSA over eth_sign hash (L92-L101);  else -> ECDSA (L103)
 * then the signer must be in the session's owner list (OwnableValidator L349).
 * => code at the session EOA can authorise THAT session without the key; no other session.
 */
contract RevocationTest is SessionTestBase {
    uint192 internal nonceKey;

    function setUp() public override {
        super.setUp();
        nonceKey = uint192(bytes24(bytes20(address(smartSession))));
    }

    function _compromise() internal {
        vm.signAndAttachDelegation(address(new MaliciousDelegation()), sessionKeyPk);
    }

    function _revoke(PermissionId id) internal {
        _execLeadership(
            address(smartSession), abi.encodeCall(ISmartSession.removeSession, (id)), Enum.Operation.Call
        );
    }

    /// @dev CheckNSignatures contract signature (v = 0) naming the session EOA, verified by its own code.
    function _hijackSig(PermissionId id) internal view returns (bytes memory) {
        return EncodeLib.encodeUse(
            id,
            abi.encodePacked(
                bytes32(uint256(uint160(sessionKey))), bytes32(uint256(65)), uint8(0), uint256(0)
            )
        );
    }

    /// @dev Pre-signs `n` ops with consecutive future nonces, both as ECDSA and as hijacked
    ///      contract signatures.
    function _presign(uint256 n)
        internal
        view
        returns (PackedUserOperation[] memory ecdsa, PackedUserOperation[] memory hijack)
    {
        ecdsa = new PackedUserOperation[](n);
        hijack = new PackedUserOperation[](n);
        uint256 base = entryPoint.getNonce(address(safe), nonceKey);
        for (uint256 i; i < n; i++) {
            PackedUserOperation memory op = _userOp(_singleCall(alice, 1 ether, ""));
            op.nonce = base + i;
            ecdsa[i] = _signAs(op, sessionKeyPk, permissionId);
            PackedUserOperation memory h = _userOp(_singleCall(bob, 1 ether, ""));
            h.nonce = base + i;
            h.signature = _hijackSig(permissionId);
            hijack[i] = h;
        }
    }

    /*//////////////////////////////////////////////////////////////
                  REVOCATION IS INDEPENDENT OF THE SIGNER
    //////////////////////////////////////////////////////////////*/

    /// The attacker uses the session as hard as it can right up to revocation; leadership's
    /// removeSession is a Safe transaction (Safe nonce, owner signatures) the session cannot touch.
    function test_R_attackerCannotPreventRevocation() public {
        _compromise();
        for (uint256 i; i < 5; i++) {
            _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        }
        // Session attempts to "protect" itself: all blocked (see PrivilegeEscalation for the full set).
        _assertRejectedInValidation(
            _sessionOp(
                _singleCall(
                    address(smartSession), 0, abi.encodeCall(ISmartSession.removeSession, (permissionId))
                )
            ),
            abi.encodeWithSignature("NoPoliciesSet(bytes32)", permissionId)
        );
        uint256 safeNonce = safe.nonce();
        _revoke(permissionId);
        assertEq(safe.nonce(), safeNonce + 1);
        assertFalse(smartSession.isPermissionEnabled(permissionId, address(safe)));
        assertFalse(smartSession.isISessionValidatorSet(permissionId, address(safe)), "signer config wiped");
    }

    /*//////////////////////////////////////////////////////////////
               NOTHING PRE-SIGNED SURVIVES REVOCATION
    //////////////////////////////////////////////////////////////*/

    /// Pre-signed ops for the next 5 nonces (ECDSA and hijacked contract signatures) all die, and
    /// stay dead while ANOTHER session advances the shared nonce sequence past them.
    function test_R_presignedOpsDieAndStayDead() public {
        _compromise();
        (address k2, uint256 pk2) = makeAddrAndKey("desk2");
        PermissionId id2 = _enableSession(_exchangeSession(k2, bytes32(uint256(2)), _defaultRecipients()));
        (PackedUserOperation[] memory ecdsa, PackedUserOperation[] memory hijack) = _presign(5);

        _revoke(permissionId);

        bytes memory revoked = abi.encodeWithSignature("InvalidPermissionId(bytes32)", permissionId);
        for (uint256 i; i < 5; i++) {
            // Each pre-signed op becomes nonce-valid exactly when the shared sequence reaches it...
            assertEq(entryPoint.getNonce(address(safe), nonceKey), ecdsa[i].nonce);
            _assertRejectedInValidation(ecdsa[i], revoked);
            _assertRejectedInValidation(hijack[i], revoked);
            // ...and desk2 legitimately consumes that nonce.
            _submit(_signAs(_userOp(_singleCall(alice, 0.1 ether, "")), pk2, id2));
        }
        assertEq(bob.balance, 0);
        assertEq(alice.balance, 0.5 ether, "only desk2's transfers executed");
    }

    /// Uninstalling SmartSession (emergency, all sessions) also kills pre-signed ops of every kind.
    function test_R_emergencyUninstallKillsPresignedOps() public {
        _compromise();
        (PackedUserOperation[] memory ecdsa, PackedUserOperation[] memory hijack) = _presign(1);
        _execLeadership(
            address(safe),
            abi.encodeWithSignature(
                "uninstallModule(uint256,address,bytes)", 1, address(smartSession), abi.encode(address(1), "")
            ),
            Enum.Operation.Call
        );
        _assertRejectedByEntryPoint(ecdsa[0], "AA24 signature error");
        _assertRejectedByEntryPoint(hijack[0], "AA24 signature error");
    }

    /*//////////////////////////////////////////////////////////////
          HAZARD: re-enabling the SAME key with the SAME salt
    //////////////////////////////////////////////////////////////*/

    /// permissionId = keccak256(validator, validatorInitData(signer), salt): it does not depend on the
    /// policies. Re-enabling the same signer with the same salt recreates the same permissionId, and
    /// any pre-signed op whose nonce is still unused becomes valid again. Documented operational
    /// rule: never re-enable a revoked key; rotate keys (a new signer is a new permissionId).
    function test_R_hazard_reEnableSameKeySameSaltRevivesPresignedOps() public {
        (PackedUserOperation[] memory ecdsa,) = _presign(1);
        _revoke(permissionId);
        _assertRejectedInValidation(
            ecdsa[0], abi.encodeWithSignature("InvalidPermissionId(bytes32)", permissionId)
        );

        PermissionId again = _enableSession(_exchangeSession(sessionKey, bytes32(0), _defaultRecipients()));
        assertEq(PermissionId.unwrap(again), PermissionId.unwrap(permissionId), "same permissionId");
        _submit(ecdsa[0]); // revived
        assertEq(alice.balance, 1 ether);
    }

    function test_R_reEnableWithNewSaltOrNewKeyDoesNotRevive() public {
        (PackedUserOperation[] memory ecdsa,) = _presign(1);
        _revoke(permissionId);

        // Same key, new salt -> new permissionId; old signatures name the old one.
        PermissionId newSalt =
            _enableSession(_exchangeSession(sessionKey, bytes32(uint256(7)), _defaultRecipients()));
        assertTrue(PermissionId.unwrap(newSalt) != PermissionId.unwrap(permissionId));
        _assertRejectedInValidation(
            ecdsa[0], abi.encodeWithSignature("InvalidPermissionId(bytes32)", permissionId)
        );

        // New key, same salt -> new permissionId as well.
        (address k2,) = makeAddrAndKey("rotated");
        PermissionId rotated = _enableSession(_exchangeSession(k2, bytes32(0), _defaultRecipients()));
        assertTrue(PermissionId.unwrap(rotated) != PermissionId.unwrap(permissionId));
        _assertRejectedInValidation(
            ecdsa[0], abi.encodeWithSignature("InvalidPermissionId(bytes32)", permissionId)
        );
    }

    /// Burning nonces is NOT a revocation mechanism: EntryPoint nonces are per key and shared by all
    /// sessions, and incrementNonce invalidates one sequence number at a time.
    function test_R_nonceBurnIsNotRevocation() public {
        (PackedUserOperation[] memory ecdsa,) = _presign(2);
        _execLeadership(
            address(entryPoint),
            abi.encodeWithSignature("incrementNonce(uint192)", nonceKey),
            Enum.Operation.Call
        );
        _assertRejectedByEntryPoint(ecdsa[0], "AA25 invalid account nonce");
        _submit(ecdsa[1]); // the next pre-signed op is still valid
        assertEq(alice.balance, 1 ether);
    }
}
