// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { SessionTestBase, ISafeAdmin } from "./utils/SessionTestBase.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { ISafe7579 } from "safe7579/ISafe7579.sol";
import { IERC7484 } from "safe7579/interfaces/IERC7484.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { EncodeLib } from "smartsessions/lib/EncodeLib.sol";
import { SudoPolicy } from "smartsessions/external/policies/SudoPolicy.sol";
import { SpendingLimitPolicy } from "src/policies/SpendingLimitPolicy.sol";
import {
    Session,
    PermissionId,
    ActionData,
    PolicyData,
    EnableSession,
    ChainDigest,
    SmartSessionMode
} from "smartsessions/DataTypes.sol";

/**
 * Test B - privilege escalation with the session key. Every attempt must be rejected, and the
 * Safe's owners, threshold, modules, guard, fallback handler, singleton, balances and session
 * state must be unchanged afterwards.
 */
contract PrivilegeEscalationTest is SessionTestBase {
    address internal constant SENTINEL = address(0x1);
    CriticalConfig internal before;

    function setUp() public override {
        super.setUp();
        before = _snapshot();
    }

    /// @dev Session tries `execute(Safe, adminCall)`: a Safe self-call. FunctionWhitelist forbids
    ///      the account as a target regardless of configuration.
    function _assertSelfCallBlocked(bytes memory adminCall) internal {
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(safe), 0, adminCall)), _policyViolation(address(functionPolicy))
        );
        _assertUnchanged(before);
    }

    /// @dev Session puts an account-management call directly in userOp.callData (not `execute`).
    ///      SmartSession requires an explicitly configured action for that selector - there is none.
    function _assertDirectAccountCallBlocked(bytes memory accountCall) internal {
        _assertRejectedInValidation(
            _sessionOp(accountCall), abi.encodeWithSignature("NoPoliciesSet(bytes32)", permissionId)
        );
        _assertUnchanged(before);
    }

    /// @dev Session calls SmartSession itself to reconfigure sessions. SmartSession routes that to a
    ///      dedicated sentinel action that must be explicitly granted - it never is.
    function _assertSmartSessionCallBlocked(bytes memory call) internal {
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(smartSession), 0, call)),
            abi.encodeWithSignature("NoPoliciesSet(bytes32)", permissionId)
        );
        _assertUnchanged(before);
    }

    /*//////////////////////////////////////////////////////////////
                          SAFE OWNERSHIP
    //////////////////////////////////////////////////////////////*/

    function test_B_addAttackerAsOwner() public {
        _assertSelfCallBlocked(abi.encodeCall(ISafeAdmin.addOwnerWithThreshold, (attacker, 1)));
        assertFalse(safe.isOwner(attacker));
    }

    function test_B_reduceThreshold() public {
        _assertSelfCallBlocked(abi.encodeCall(ISafeAdmin.changeThreshold, (1)));
        assertEq(safe.getThreshold(), THRESHOLD);
    }

    function test_B_removeOwner() public {
        _assertSelfCallBlocked(abi.encodeCall(ISafeAdmin.removeOwner, (SENTINEL, owners[0], 2)));
    }

    /// @dev Using the Safe's own execTransaction as an inner call (would also need owner signatures).
    function test_B_innerExecTransaction() public {
        bytes memory inner = abi.encodeWithSignature(
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
            attacker,
            1 ether,
            "",
            0,
            0,
            0,
            0,
            address(0),
            address(0),
            ""
        );
        _assertSelfCallBlocked(inner);
    }

    /*//////////////////////////////////////////////////////////////
                    MODULES, GUARD, FALLBACK, UPGRADES
    //////////////////////////////////////////////////////////////*/

    function test_B_enableUnrestrictedSafeModule() public {
        _assertSelfCallBlocked(abi.encodeCall(ISafeAdmin.enableModule, (attacker)));
    }

    function test_B_disableSafe7579Module() public {
        _assertSelfCallBlocked(abi.encodeCall(ISafeAdmin.disableModule, (SENTINEL, address(safe7579))));
    }

    function test_B_setGuard() public {
        _assertSelfCallBlocked(abi.encodeCall(ISafeAdmin.setGuard, (attacker)));
        _assertSelfCallBlocked(abi.encodeCall(ISafeAdmin.setGuard, (address(0))));
    }

    function test_B_replaceFallbackHandler() public {
        _assertSelfCallBlocked(abi.encodeCall(ISafeAdmin.setFallbackHandler, (attacker)));
    }

    function test_B_install7579ExecutorViaSelfCall() public {
        _assertSelfCallBlocked(abi.encodeCall(ISafe7579.installModule, (2, attacker, "")));
    }

    function test_B_install7579ExecutorDirectly() public {
        _assertDirectAccountCallBlocked(abi.encodeCall(ISafe7579.installModule, (2, attacker, "")));
    }

    function test_B_install7579HookDirectly() public {
        _assertDirectAccountCallBlocked(
            abi.encodeCall(ISafe7579.installModule, (4, attacker, abi.encode(uint8(0), bytes4(0), "")))
        );
    }

    function test_B_uninstallSmartSessionValidator() public {
        _assertDirectAccountCallBlocked(
            abi.encodeCall(ISafe7579.uninstallModule, (1, address(smartSession), abi.encode(SENTINEL, "")))
        );
    }

    function test_B_changeAdapterRegistry() public {
        _assertDirectAccountCallBlocked(
            abi.encodeCall(ISafe7579.setRegistry, (IERC7484(attacker), new address[](0), 0))
        );
    }

    /// @dev Safe v1.4.1 has no upgrade function: changing the singleton requires a DELEGATECALL
    ///      from the Safe. Sessions can only CALL (DELEGATECALL mode is rejected, see PolicyEnforcement).
    function test_B_upgradeViaDelegatecallIsUnreachable() public {
        _assertSelfCallBlocked(
            abi.encodeWithSignature(
                "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
                attacker,
                0,
                abi.encodeWithSignature("migrate()"),
                uint8(1),
                0,
                0,
                0,
                address(0),
                address(0),
                ""
            )
        );
        assertEq(before.singletonSlot, vm.load(address(safe), bytes32(0)));
    }

    /*//////////////////////////////////////////////////////////////
                    SESSION SELF-MANAGEMENT (SmartSession)
    //////////////////////////////////////////////////////////////*/

    function test_B_changeOwnWhitelist() public {
        address[] memory r = new address[](1);
        r[0] = attacker;
        _assertSmartSessionCallBlocked(
            abi.encodeCall(
                ISmartSession.enableActionPolicies,
                (permissionId, _catchAllAction(address(addressPolicy), abi.encode(r)))
            )
        );
        assertFalse(
            addressPolicy.isWhitelisted(actionConfigId, address(smartSession), address(safe), attacker)
        );
    }

    function test_B_increaseOwnSpendingLimit() public {
        _assertSmartSessionCallBlocked(
            abi.encodeCall(
                ISmartSession.enableActionPolicies,
                (permissionId, _catchAllAction(address(spendingPolicy), abi.encode(_hugeLimits())))
            )
        );
    }

    function test_B_installUnrestrictedSudoPolicy() public {
        SudoPolicy sudo = new SudoPolicy();
        _assertSmartSessionCallBlocked(
            abi.encodeCall(
                ISmartSession.enableActionPolicies, (permissionId, _catchAllAction(address(sudo), ""))
            )
        );
    }

    function test_B_createNewUnrestrictedSession() public {
        Session[] memory list = new Session[](1);
        list[0] = _exchangeSession(attacker, bytes32(uint256(666)), _defaultRecipients());
        _assertSmartSessionCallBlocked(abi.encodeCall(ISmartSession.enableSessions, (list)));
    }

    function test_B_removeOtherSessionOrUnrevokeSelf() public {
        _assertSmartSessionCallBlocked(abi.encodeCall(ISmartSession.removeSession, (permissionId)));
    }

    /// @dev Calling a policy's initializer *through the Safe* would write the Safe's namespace.
    function test_B_reconfigurePolicyThroughSafe() public {
        address[] memory r = new address[](1);
        r[0] = attacker;
        bytes memory call = abi.encodeCall(
            addressPolicy.initializeWithMultiplexer, (address(safe), actionConfigId, abi.encode(r))
        );
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(addressPolicy), 0, call)),
            _policyViolation(address(functionPolicy))
        );
    }

    /// @dev Calling a policy's initializer *directly* only writes the caller's own namespace.
    function test_B_reconfigurePolicyDirectly() public {
        address[] memory r = new address[](1);
        r[0] = attacker;
        vm.prank(sessionKey);
        addressPolicy.initializeWithMultiplexer(address(safe), actionConfigId, abi.encode(r));

        assertTrue(
            addressPolicy.isWhitelisted(actionConfigId, sessionKey, address(safe), attacker), "own namespace"
        );
        assertFalse(
            addressPolicy.isWhitelisted(actionConfigId, address(smartSession), address(safe), attacker),
            "real config"
        );
        _assertRejectedInValidation(
            _sessionOp(_singleCall(attacker, 1 ether, "")), _policyViolation(address(addressPolicy))
        );
    }

    /*//////////////////////////////////////////////////////////////
               SMARTSESSIONS "ENABLE MODE" (in-userOp session creation)
    //////////////////////////////////////////////////////////////*/

    /// @dev Enable mode lets a userOp carry a new session + the ACCOUNT's signature over it. The
    ///      session key cannot produce that signature: Safe7579 falls back to Safe.checkSignatures.
    function test_B_enableModeWithForgedSafeSignature() public {
        (EnableSession memory e, PermissionId newId) = _maliciousEnable();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, keccak256("anything"));
        // 20-byte validator selector address(0) -> Safe owners' checkSignatures path.
        e.permissionEnableSig = abi.encodePacked(address(0), r, s, v);

        PackedUserOperation memory op = _userOp(_singleCall(attacker, 50 ether, ""));
        op.signature = _enableSig(e, op);

        _assertRejectedInValidation(op, abi.encodeWithSignature("Error(string)", "GS020"));
        assertFalse(smartSession.isPermissionEnabled(newId, address(safe)));
        _assertUnchanged(before);
    }

    /// @dev Same, but routing the account signature back into SmartSession's own ERC-1271 - which
    ///      refuses to authorise its own enable flow.
    function test_B_enableModeViaSessionErc1271() public {
        (EnableSession memory e, PermissionId newId) = _maliciousEnable();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, keccak256("anything"));
        e.permissionEnableSig = abi.encodePacked(address(smartSession), permissionId, r, s, v);

        PackedUserOperation memory op = _userOp(_singleCall(attacker, 50 ether, ""));
        op.signature = _enableSig(e, op);

        // Selector-only match: the second argument is the multichain digest computed inside SmartSession.
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        vm.prank(address(safe));
        vm.expectPartialRevert(ISmartSession.InvalidEnableSignature.selector);
        smartSession.validateUserOp(op, userOpHash);
        _assertRejectedByEntryPointAA23(op);
        assertFalse(smartSession.isPermissionEnabled(newId, address(safe)));
        _assertUnchanged(before);
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-1271: signing *as the Safe*
    //////////////////////////////////////////////////////////////*/

    /// @dev The session has no ERC-7739 content and no ERC-1271 policy, so it can never make the Safe
    ///      "sign" anything (e.g. a Permit2 / off-chain order that would pull funds later).
    function test_B_sessionCannotProduceSafeErc1271Signature() public view {
        assertEq(smartSession.getERC1271Policies(address(safe), permissionId).length, 0);
        bytes32 hash = keccak256("Permit2: transfer all USDC to attacker");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, hash);

        assertFalse(_safeAccepts1271(hash, abi.encodePacked(address(smartSession), permissionId, r, s, v)));
        assertFalse(_safeAccepts1271(hash, abi.encodePacked(address(0), r, s, v)));
        assertFalse(_safeAccepts1271(hash, abi.encodePacked(address(ownableValidator), r, s, v)));
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _safeAccepts1271(bytes32 hash, bytes memory sig) internal view returns (bool) {
        (bool ok, bytes memory ret) =
            address(safe).staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", hash, sig));
        return ok && ret.length >= 32 && bytes4(ret) == bytes4(0x1626ba7e);
    }

    function _hugeLimits() internal pure returns (SpendingLimitPolicy.AssetLimit[] memory l) {
        l = new SpendingLimitPolicy.AssetLimit[](1);
        l[0] = SpendingLimitPolicy.AssetLimit({
            asset: address(0), maxPerTx: 1000 ether, maxPerPeriod: 1000 ether, period: 1 days
        });
    }

    function _maliciousEnable() internal returns (EnableSession memory e, PermissionId newId) {
        SudoPolicy sudo = new SudoPolicy();
        Session memory s = _exchangeSession(sessionKey, bytes32(uint256(777)), _defaultRecipients());
        s.actions = _catchAllAction(address(sudo), "");
        newId = smartSession.getPermissionId(s);

        e.chainDigestIndex = 0;
        e.hashesAndChainIds = new ChainDigest[](1);
        e.hashesAndChainIds[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: smartSession.getSessionDigest(
                newId, address(safe), s, SmartSessionMode.UNSAFE_ENABLE
            )
        });
        e.sessionToEnable = s;
    }

    function _enableSig(EnableSession memory e, PackedUserOperation memory op)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, entryPoint.getUserOpHash(op));
        return EncodeLib.encodeUnsafeEnable(abi.encodePacked(r, s, v), e);
    }
}
