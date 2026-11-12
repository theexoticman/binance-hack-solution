// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { MultiSendCallOnly } from "@safe-global/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";
import { ExecutionOptions } from "zodiac-roles/Types.sol";
import { SentinelSafeBase, ISentinelOracle, ISafeAdmin, FeeToken } from "./SentinelSafeBase.sol";
import { SentinelSetup, EngineEntry, OwnerCall } from "script/sentinel/SentinelSetup.sol";

/**
 * @notice Safenet sentinel = Safe; server = Roles SENTINEL key; Safe Policy Engine = floor.
 *         Runs against the real SentinelOracle (lib/safenet @ c355af1).
 *
 *   allow_*     the six calls the sentinel service sends, normal and disputed paths
 *   block_*     each prohibited action tried three ways (see `_assertBlocked`)
 *   rotation_*  replacing a leaked key / a departing employee's key
 *   market_*    adding or removing a fee token
 *   migration_* moving an existing EOA sentinel to the Safe
 *   finding_*   behaviour worth knowing that is not a failure of the setup
 */
contract SentinelSafeTest is SentinelSafeBase {
    bytes32 internal constant SALT = keccak256("salt");

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function test_setup_entriesAndGuards() public view {
        assertEq(_entries().length, 14, "7 admin + 7 for the USDC.e market");
        assertEq(vm.load(address(safe), GUARD_SLOT), bytes32(uint256(uint160(address(guard)))));
        assertEq(vm.load(address(safe), MODULE_GUARD_SLOT), bytes32(uint256(uint160(address(guard)))));
        (address[] memory modules,) = safe.getModulesPaginated(SENTINEL_LIST, 10);
        assertEq(modules.length, 1);
        assertEq(modules[0], address(roles));
    }

    function test_setup_selectorsMatchTheOracleAbi() public pure {
        assertEq(SentinelSetup.COMMIT, ISentinelOracle.commit.selector);
        assertEq(SentinelSetup.REVEAL, ISentinelOracle.reveal.selector);
        assertEq(SentinelSetup.FINALIZE, ISentinelOracle.finalize.selector);
        assertEq(SentinelSetup.CLAIM, ISentinelOracle.claim.selector);
        assertEq(SentinelSetup.TIMEOUT_ARBITRATION, ISentinelOracle.timeoutArbitration.selector);
        assertEq(SentinelSetup.APPROVE, ERC20.approve.selector);
    }

    /*//////////////////////////////////////////////////////////////
                              ALLOWED PATHS
    //////////////////////////////////////////////////////////////*/

    /// approve -> commit -> reveal (auto-finalizes) -> claim. The Safe earns the fee; the key holds nothing.
    function test_allow_normalPath() public {
        bytes32 id = _id(1);
        _post(oracle, id);
        uint256 s0 = usdce.balanceOf(address(safe));

        _commitAsSafe(oracle, address(usdce), id, true, SALT);
        assertEq(usdce.balanceOf(address(safe)), s0 - BOND, "bond pulled from the Safe");

        _toRevealWindow();
        _revealAsSafe(oracle, id, true, SALT);
        _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.claim, (id)));

        assertEq(usdce.balanceOf(address(safe)), s0 + REQUEST_FEE, "bond back + fee reward, to the Safe");
        assertEq(usdce.balanceOf(server.addr), 0, "the key never holds the fee token");
        assertEq(usdce.allowance(address(safe), address(oracle)), 0, "no leftover allowance");
    }

    function test_allow_finalizeAfterRevealDeadline() public {
        bytes32 id = _id(2);
        _post(oracle, id);
        uint256 s0 = usdce.balanceOf(address(safe));

        _commitAsSafe(oracle, address(usdce), id, true, SALT);
        _commitAs(peer.addr, id, true, SALT); // the peer never reveals
        _toRevealWindow();
        _revealAsSafe(oracle, id, true, SALT);
        _pastRevealDeadline();
        _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.finalize, (id)));
        _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.claim, (id)));

        assertEq(usdce.balanceOf(address(safe)), s0 + REQUEST_FEE);
    }

    function test_allow_disputedPath_timeoutArbitrationThenClaim() public {
        bytes32 id = _id(3);
        _post(oracle, id);
        uint256 s0 = usdce.balanceOf(address(safe));

        _commitAsSafe(oracle, address(usdce), id, true, SALT);
        _commitAs(peer.addr, id, false, SALT);
        _toRevealWindow();
        _revealAsSafe(oracle, id, true, SALT);
        _revealAs(peer.addr, id, false, SALT); // both sides established: FROZEN

        (bool ok,) = _send(server, address(oracle), abi.encodeCall(ISentinelOracle.claim, (id)));
        assertFalse(ok, "nothing to claim while frozen");

        vm.roll(block.number + ARBITRATION_TIMEOUT + 1);
        _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.timeoutArbitration, (id)));
        _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.claim, (id)));

        assertEq(usdce.balanceOf(address(safe)), s0, "bond returned in full");
    }

    function test_allow_approveUpTo800() public {
        _sendOrFail(address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), MAX_BOND)));
        assertEq(usdce.allowance(address(safe), address(oracle)), MAX_BOND);
        _sendOrFail(address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), 0)));
        assertEq(usdce.allowance(address(safe), address(oracle)), 0);
    }

    function test_allow_killSwitch() public {
        _ownerExecOrFail(
            address(safe), 0, abi.encodeCall(ISafeAdmin.disableModule, (SENTINEL_LIST, address(roles))), 0
        );
        (bool ok,) = _send(server, address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), BOND)));
        assertFalse(ok, "Roles detached: the key can do nothing");
    }

    function test_allow_ownerWithdrawToTreasuryOnly() public {
        (bool toTreasury,) =
            _ownerExec(address(usdce), 0, abi.encodeCall(ERC20.transfer, (treasury, 100e6)), 0);
        (bool toAttacker, bytes memory reason) =
            _ownerExec(address(usdce), 0, abi.encodeCall(ERC20.transfer, (attacker, 100e6)), 0);
        assertTrue(toTreasury);
        assertFalse(toAttacker);
        assertTrue(_isEngineDenial(reason));
    }

    /*//////////////////////////////////////////////////////////////
                              BLOCKED PATHS
    //////////////////////////////////////////////////////////////*/

    /**
     * Each prohibited action, three ways, asserting no effect on the Safe each time:
     *   1. real path: the SENTINEL key asks Roles;                  Roles refuses
     *   2. module compromise: Roles itself asks the Safe;           the Policy Engine refuses
     *   3. misconfiguration: Roles opened for the target, then 1;   the Policy Engine refuses
     */
    function _assertBlocked(Exec memory e, string memory label) internal {
        Effects memory before = _effects();
        (bool ok, bytes memory reason) = _send(server, e);
        assertFalse(ok, string.concat(label, ": key"));
        _assertNoEffects(before, label);

        (ok, reason) = _asModule(e);
        assertFalse(ok, string.concat(label, ": module"));
        assertTrue(_isEngineDenial(reason), string.concat(label, ": module, engine denial"));
        _assertNoEffects(before, label);

        _openRoles(e.to);
        before = _effects();
        (ok, reason) = _send(server, e);
        assertFalse(ok, string.concat(label, ": misconfigured Roles"));
        assertTrue(_isEngineDenial(reason), string.concat(label, ": misconfigured Roles, engine denial"));
        _assertNoEffects(before, label);
    }

    function test_block_approveAnotherSpender() public {
        _assertBlocked(
            Exec(address(usdce), 0, abi.encodeCall(ERC20.approve, (attacker, BOND)), 0), "approve attacker"
        );
        _assertBlocked(
            Exec(address(usdce), 0, abi.encodeCall(ERC20.approve, (attacker, 0)), 0), "approve attacker 0"
        );
    }

    function test_block_approveAbove800() public {
        _assertBlocked(
            Exec(address(usdce), 0, abi.encodeCall(ERC20.approve, (address(oracle), MAX_BOND + 1)), 0),
            "approve 801"
        );
    }

    function test_block_moveFunds() public {
        _assertBlocked(
            Exec(address(usdce), 0, abi.encodeCall(ERC20.transfer, (attacker, 1e6)), 0), "transfer"
        );
        _assertBlocked(Exec(attacker, 1 ether, "", 0), "send ETH");
    }

    function test_block_otherOracleFunctions() public {
        _assertBlocked(Exec(address(oracle), 0, abi.encodeCall(ISentinelOracle.applyFee, ()), 0), "applyFee");
        _assertBlocked(
            Exec(address(oracle), 0, abi.encodeCall(ISentinelOracle.addSentinel, (attacker)), 0),
            "addSentinel"
        );
    }

    function test_block_delegatecall() public {
        _assertBlocked(
            Exec(address(oracle), 0, abi.encodeCall(ISentinelOracle.claim, (_id(1))), 1), "to oracle"
        );
        _assertBlocked(
            Exec(address(usdce), 0, abi.encodeCall(ERC20.approve, (address(oracle), BOND)), 1), "to fee token"
        );
    }

    function test_block_multiSend() public {
        Exec memory batch = Exec(
            address(multiSend),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (SentinelSetup.toMultiSend(
                        _one(address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), BOND)))
                    ))
            ),
            1
        );
        _assertBlocked(batch, "MultiSend (delegatecall)");
        batch.operation = 0;
        _assertBlocked(batch, "MultiSend (call)");
    }

    /// After setup the owners cannot batch either, not even calls they could make one by one.
    function test_block_multiSendForOwners() public {
        (bool ok, bytes memory reason) =
            _ownerBatch(_one(address(usdce), abi.encodeCall(ERC20.transfer, (treasury, 1e6))));
        assertFalse(ok);
        assertTrue(_isEngineDenial(reason));
    }

    function test_block_safeAdministration() public {
        address s = address(safe);
        _assertBlocked(
            Exec(s, 0, abi.encodeCall(ISafeAdmin.addOwnerWithThreshold, (attacker, 1)), 0), "addOwner"
        );
        _assertBlocked(Exec(s, 0, abi.encodeCall(ISafeAdmin.changeThreshold, (1)), 0), "changeThreshold");
        _assertBlocked(Exec(s, 0, abi.encodeCall(ISafeAdmin.enableModule, (attacker)), 0), "enableModule");
        _assertBlocked(
            Exec(s, 0, abi.encodeCall(ISafeAdmin.disableModule, (SENTINEL_LIST, address(roles))), 0),
            "disableModule"
        );
        _assertBlocked(Exec(s, 0, abi.encodeCall(ISafeAdmin.setGuard, (address(0))), 0), "setGuard");
        _assertBlocked(
            Exec(s, 0, abi.encodeCall(ISafeAdmin.setModuleGuard, (address(0))), 0), "setModuleGuard"
        );
        _assertBlocked(
            Exec(s, 0, abi.encodeCall(ISafeAdmin.setFallbackHandler, (attacker)), 0), "setFallbackHandler"
        );
    }

    /// A leaked key cannot grant itself or anyone more, or another key the role.
    function test_block_rolesAdministration() public {
        address r = address(roles);
        OwnerCall memory grant = SentinelSetup.rolesAssign(r, attacker, true);
        _assertBlocked(Exec(r, 0, grant.data, 0), "assignRoles attacker");
        _assertBlocked(
            Exec(r, 0, abi.encodeWithSelector(SentinelSetup.SCOPE_TARGET, SentinelSetup.ROLE, attacker), 0),
            "scopeTarget"
        );
        _assertBlocked(
            Exec(
                r,
                0,
                abi.encodeCall(roles.allowTarget, (SentinelSetup.ROLE, attacker, ExecutionOptions.Both)),
                0
            ),
            "allowTarget"
        );
        (bool ok,) =
            _send(Key(attacker, 0), address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), 1)));
        assertFalse(ok, "attacker never became a member");
    }

    function test_block_valueOnOracleCall() public {
        Effects memory before = _effects();
        (bool ok,) =
            _send(server, Exec(address(oracle), 1 wei, abi.encodeCall(ISentinelOracle.claim, (_id(1))), 0));
        assertFalse(ok, "ExecutionOptions.None: no ETH");
        _assertNoEffects(before, "value");
    }

    /*//////////////////////////////////////////////////////////////
                              KEY ROTATION
    //////////////////////////////////////////////////////////////*/

    /// Leak or departure: one owner tx revokes the key immediately, one more grants the replacement.
    /// No engine delay, no new Safe, no Safenet governance action: the sentinel address stays the Safe.
    function test_rotation_revokeThenGrant() public {
        Key memory next = _newKey("nextServerKey");
        bytes memory approveBond = abi.encodeCall(ERC20.approve, (address(oracle), BOND));

        _ownerCallOrFail(SentinelSetup.rolesAssign(address(roles), server.addr, false));
        (bool ok,) = _send(server, address(usdce), approveBond);
        assertFalse(ok, "revoked key is dead immediately");

        _ownerCallOrFail(SentinelSetup.rolesAssign(address(roles), next.addr, true));
        (ok,) = _send(next, address(usdce), approveBond);
        assertTrue(ok, "replacement works immediately");
    }

    /// Commitments belong to the Safe, so a request committed with the old key is revealed and
    /// claimed with the new one.
    function test_rotation_inFlightRequestSurvives() public {
        bytes32 id = _id(10);
        _post(oracle, id);
        uint256 s0 = usdce.balanceOf(address(safe));
        _commitAsSafe(oracle, address(usdce), id, true, SALT);

        Key memory oldKey = server;
        server = _newKey("nextServerKey");
        _ownerCallOrFail(SentinelSetup.rolesAssign(address(roles), oldKey.addr, false));
        _ownerCallOrFail(SentinelSetup.rolesAssign(address(roles), server.addr, true));

        _toRevealWindow();
        _revealAsSafe(oracle, id, true, SALT);
        _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.claim, (id)));
        assertEq(usdce.balanceOf(address(safe)), s0 + REQUEST_FEE);
    }

    /// The owners still need the normal threshold for rotation: the role key cannot rotate itself.
    function test_rotation_isOwnerOnly() public {
        OwnerCall memory c = SentinelSetup.rolesAssign(address(roles), attacker, true);
        (bool ok, bytes memory reason) = _asModule(Exec(c.to, 0, c.data, 0));
        assertFalse(ok);
        assertTrue(_isEngineDenial(reason));
    }

    /*//////////////////////////////////////////////////////////////
                            ADDING A FEE TOKEN
    //////////////////////////////////////////////////////////////*/

    /// A new fee token means a new oracle (FEE_TOKEN is immutable). Engine entries take the delay;
    /// the Roles side is single owner txs. Nothing changes for the existing market or the key.
    function test_market_addNewFeeToken() public {
        FeeToken token2 = new FeeToken("New fee token", "NEW");
        ISentinelOracle oracle2 = _deployOracle(address(token2));
        _prepareCounterparties(address(token2), oracle2);
        _fund(address(token2), address(safe), 10_000e6);
        vm.prank(governance);
        oracle2.addSentinel(address(safe));
        vm.roll(block.number + GOVERNANCE_DELAY);

        SentinelSetup.Market memory m2 =
            SentinelSetup.Market({ feeToken: address(token2), oracle: address(oracle2), maxBond: MAX_BOND });
        EngineEntry[] memory entries = SentinelSetup.marketEntries(m2, treasury, pol);

        // Engine: request, wait the delay, apply.
        _ownerExecOrFail(address(guard), 0, SentinelSetup.requestConfiguration(entries), 0);
        (bool ok, bytes memory reason) =
            _ownerExec(address(guard), 0, SentinelSetup.applyConfiguration(entries), 0);
        assertFalse(ok, "not before the delay");
        assertEq(bytes4(reason), bytes4(keccak256("RootConfigurationPending()")));
        vm.warp(block.timestamp + POLICY_DELAY);
        _ownerExecOrFail(address(guard), 0, SentinelSetup.applyConfiguration(entries), 0);

        // Roles: one owner tx per call.
        OwnerCall[] memory calls = SentinelSetup.rolesAddMarket(address(roles), m2);
        for (uint256 i; i < calls.length; i++) {
            _ownerCallOrFail(calls[i]);
        }

        bytes32 id = _id(20);
        _post(oracle2, id);
        _commitAsSafe(oracle2, address(token2), id, true, SALT);
        assertEq(token2.balanceOf(address(safe)), 10_000e6 - BOND);

        // Spenders stay per market: the new token cannot be approved to the old oracle.
        (ok,) = _send(server, address(token2), abi.encodeCall(ERC20.approve, (address(oracle), BOND)));
        assertFalse(ok, "new token, old oracle");
    }

    /// Before the engine delay has passed, the Roles side alone opens nothing.
    function test_market_rolesAloneIsNotEnough() public {
        FeeToken token2 = new FeeToken("New fee token", "NEW");
        ISentinelOracle oracle2 = _deployOracle(address(token2));
        SentinelSetup.Market memory m2 =
            SentinelSetup.Market({ feeToken: address(token2), oracle: address(oracle2), maxBond: MAX_BOND });
        OwnerCall[] memory calls = SentinelSetup.rolesAddMarket(address(roles), m2);
        for (uint256 i; i < calls.length; i++) {
            _ownerCallOrFail(calls[i]);
        }
        (bool ok, bytes memory reason) =
            _send(server, address(token2), abi.encodeCall(ERC20.approve, (address(oracle2), BOND)));
        assertFalse(ok);
        assertTrue(_isEngineDenial(reason));
    }

    /// Removing a market from the role is immediate (two owner txs).
    function test_market_remove() public {
        OwnerCall[] memory calls = SentinelSetup.rolesRemoveMarket(address(roles), _market());
        for (uint256 i; i < calls.length; i++) {
            _ownerCallOrFail(calls[i]);
        }
        (bool ok,) = _send(server, address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), BOND)));
        assertFalse(ok);
    }

    /*//////////////////////////////////////////////////////////////
                    MIGRATION FROM AN EOA SENTINEL
    //////////////////////////////////////////////////////////////*/

    /// Today's sentinel is an EOA. Governance adds the Safe, then removes the EOA. Removal only stops
    /// NEW commits: the EOA still reveals and claims what it already committed to.
    function test_migration_eoaFinishesInFlightRequestsSafeTakesNewOnes() public {
        Key memory legacy = _newKey("legacyEoaSentinel");
        _fund(address(usdce), legacy.addr, 10_000e6);
        vm.prank(legacy.addr);
        usdce.approve(address(oracle), type(uint256).max);
        vm.prank(governance);
        oracle.addSentinel(legacy.addr);
        vm.roll(block.number + GOVERNANCE_DELAY);

        bytes32 inFlight = _id(30);
        _post(oracle, inFlight);
        _commitAs(legacy.addr, inFlight, true, SALT);

        // Cut-over (the Safe was added in setUp): remove the EOA.
        vm.prank(governance);
        oracle.removeSentinel(legacy.addr);

        bytes32 next = _id(31);
        _post(oracle, next);
        bytes32 h = oracle.hashCommitment(legacy.addr, next, true, SALT, "");
        vm.prank(legacy.addr);
        vm.expectRevert(bytes4(keccak256("SentinelNotActive()")));
        oracle.commit(next, h);
        _commitAsSafe(oracle, address(usdce), next, true, SALT);

        _toRevealWindow();
        uint256 l0 = usdce.balanceOf(legacy.addr);
        _revealAs(legacy.addr, inFlight, true, SALT);
        vm.prank(legacy.addr);
        oracle.claim(inFlight);
        assertEq(usdce.balanceOf(legacy.addr), l0 + BOND + REQUEST_FEE, "legacy EOA closes out its request");

        _revealAsSafe(oracle, next, true, SALT);
        _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.claim, (next)));
    }

    /*//////////////////////////////////////////////////////////////
                                FINDINGS
    //////////////////////////////////////////////////////////////*/

    /// The commit hash must name the SAFE: on reveal the oracle recomputes it with msg.sender = Safe.
    /// The sentinel service today hashes `self.signer.address()` (service.rs:222).
    function test_finding_commitHashMustNameTheSafe() public {
        bytes32 id = _id(40);
        _post(oracle, id);
        _sendOrFail(address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), BOND)));
        bytes32 wrong = oracle.hashCommitment(server.addr, id, true, SALT, "");
        _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.commit, (id, wrong)));
        _toRevealWindow();
        (bool ok,) = _send(
            server, address(oracle), abi.encodeCall(ISentinelOracle.reveal, (id, true, SALT, string("")))
        );
        assertFalse(ok, "a hash bound to the key address cannot be revealed");
    }

    /// Without a budget, a leaked key can bond every open request (800 each) until it is revoked.
    /// It cannot move funds anywhere else. Revocation (one owner tx) is the bound.
    function test_finding_leakedKeyCanBondEveryRequestUntilRevoked() public {
        uint256 s0 = usdce.balanceOf(address(safe));
        for (uint256 i; i < 3; i++) {
            bytes32 id = _id(50 + i);
            _post(oracle, id);
            _sendOrFail(address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), BOND)));
            _sendOrFail(address(oracle), abi.encodeCall(ISentinelOracle.commit, (id, keccak256("garbage"))));
        }
        assertEq(s0 - usdce.balanceOf(address(safe)), 3 * BOND);

        _ownerCallOrFail(SentinelSetup.rolesAssign(address(roles), server.addr, false));
        (bool ok,) = _send(server, address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), BOND)));
        assertFalse(ok);
    }

    /// With Roles itself compromised, the treasury entry lets the module move funds to the treasury,
    /// which is the owners' address: a misdirected withdrawal, not a loss.
    function test_finding_moduleCanReachTheTreasuryEntry() public {
        (bool ok,) = _asModule(Exec(address(usdce), 0, abi.encodeCall(ERC20.transfer, (treasury, 1e6)), 0));
        assertTrue(ok);
    }

    function _one(address to, bytes memory data) internal pure returns (OwnerCall[] memory c) {
        c = new OwnerCall[](1);
        c[0] = OwnerCall(to, data);
    }
}
