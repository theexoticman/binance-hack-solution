// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { OperatorKeyBase, ISafe150, IPolicyGuard, PolicyConfig } from "./utils/OperatorKeyBase.sol";
import { MultiSendCallOnly } from "@safe-global/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";
import { Safe } from "@safe-global/safe-smart-account/contracts/Safe.sol";
import { Enum } from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { UnauthorizedTarget, Drainer, TestToken } from "./utils/OperatorKeyFixtures.sol";

/**
 * @title Shared operator-key security suite
 * @notice Runs unchanged against both architectures (ZodiacRoles.t.sol, SmartSessions.t.sol).
 *
 * Every prohibited scenario is checked three ways, and each check asserts on-chain EFFECTS
 * (owners, threshold, modules, both guards, fallback handler, singleton, all balances, allowances,
 * policy entries, operator-framework state), not only revert status:
 *
 *   1. real path       - the correctly configured operator key tries it          -> blocked
 *   2. module compromise - the operator MODULE (Roles / Safe7579) itself issues
 *                        `execTransactionFromModule` with it                    -> blocked BY THE POLICY ENGINE
 *   3. misconfigured   - the operator layer is opened up for the target, then
 *                        the operator key tries it through the real path        -> blocked BY THE POLICY ENGINE
 *                        (or, where the operator layer cannot even express it,
 *                        still blocked, and the test records that)
 *
 * (2) and (3) are what establish the security invariant: no operator-authorized execution can
 * bypass Safe Policy Engine, whatever the operator layer allows.
 */
abstract contract OperatorKeySuite is OperatorKeyBase {
    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _call(address to, bytes memory data) internal pure returns (Exec memory) {
        return Exec(to, 0, data, 0);
    }

    function _transfer(TestToken token, address to, uint256 amount) internal pure returns (Exec memory) {
        return _call(address(token), abi.encodeCall(token.transfer, (to, amount)));
    }

    function _asModule(Exec memory e) internal returns (bool ok, bytes memory reason) {
        vm.prank(_operatorModule());
        (ok, reason) = address(safe)
            .call(abi.encodeCall(ISafe150.execTransactionFromModule, (e.to, e.value, e.data, e.operation)));
    }

    /// @dev (1) the real operator path refuses, with no effect.
    function _assertBlocked(Exec memory e) internal returns (bytes memory reason) {
        Effects memory before = _effects();
        bool ok;
        (ok, reason) = _operatorExec(operator, e);
        assertFalse(ok, "operator execution was not blocked");
        _assertNoEffects(before);
    }

    /// @dev (2) the operator module itself cannot get it past the Policy Engine.
    function _assertModuleCompromiseBlocked(Exec memory e) internal {
        Effects memory before = _effects();
        (bool ok, bytes memory reason) = _asModule(e);
        assertFalse(ok, "module transaction bypassed the Policy Engine");
        assertTrue(_isPolicyEngineDenial(reason), "module transaction not denied by the Policy Engine");
        _assertNoEffects(before);
    }

    /// @dev (3) with the operator layer opened up for `e.to`, the Policy Engine still blocks it.
    function _assertBlockedWhenMisconfigured(Exec memory e) internal {
        bool opened = _openOperatorLayer(operator, e.to, e.operation);
        Effects memory before = _effects();
        (bool ok, bytes memory reason) = _operatorExec(operator, e);
        assertFalse(ok, "misconfigured operator bypassed the Policy Engine");
        if (opened) assertTrue(_isPolicyEngineDenial(reason), "not denied by the Policy Engine");
        else emit log_named_string("operator layer cannot express this; blocked by", "operator layer");
        _assertNoEffects(before);
    }

    function _assertProhibited(Exec memory e) internal {
        _assertBlocked(e);
        _assertModuleCompromiseBlocked(e);
        uint256 snap = vm.snapshotState();
        _assertBlockedWhenMisconfigured(e);
        vm.revertToState(snap);
    }

    function _assertProhibitedBatch(Exec[] memory es) internal {
        Effects memory before = _effects();
        (bool ok,) = _operatorBatch(operator, es);
        assertFalse(ok, "operator batch was not blocked");
        _assertNoEffects(before);
        _assertModuleCompromiseBlocked(_batchAsModuleTx(es));
    }

    function _prevModule(address module) internal view returns (address prev) {
        (address[] memory m,) = safe.getModulesPaginated(SENTINEL, 20);
        prev = SENTINEL;
        for (uint256 i; i < m.length; i++) {
            if (m[i] == module) return prev;
            prev = m[i];
        }
        revert("module not found");
    }

    function _rotate(Key memory oldKey, Key memory newKey) internal {
        Exec[] memory txs = new Exec[](2);
        txs[0] = _registerOperatorTx(newKey.addr);
        txs[1] = _revokeOperatorTx(oldKey.addr);
        Exec memory batch = _multiSendExec(txs);
        _ownerExecOrFail(batch.to, 0, batch.data, batch.operation);
    }

    /*//////////////////////////////////////////////////////////////
                               SET-UP
    //////////////////////////////////////////////////////////////*/

    function test_setup_bothGuardsInstalled_operatorIsNotOwner() public view {
        assertEq(vm.load(address(safe), GUARD_SLOT), bytes32(uint256(uint160(address(guard)))));
        assertEq(vm.load(address(safe), MODULE_GUARD_SLOT), bytes32(uint256(uint160(address(guard)))));
        assertFalse(safe.isOwner(operator.addr));
        assertEq(safe.getThreshold(), THRESHOLD);
        (address[] memory modules,) = safe.getModulesPaginated(SENTINEL, 20);
        assertEq(modules.length, 1, "exactly one Safe module");
        assertEq(modules[0], _operatorModule());
    }

    /*//////////////////////////////////////////////////////////////
                        PERMITTED OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_S01_allow_authorizedContractAndSelector() public {
        (bool ok, bytes memory reason) = _operatorExec(operator, _transfer(usdc, alice, 400e6));
        if (!ok) _bubble(reason);
        assertEq(usdc.balanceOf(alice), 400e6);
        assertEq(usdc.balanceOf(address(safe)), SAFE_USDC - 400e6);
        assertEq(address(safe).balance, SAFE_ETH, "no ETH spent by the Safe");
    }

    function test_S01_allow_authorizedBatch() public {
        Exec[] memory es = new Exec[](2);
        es[0] = _transfer(usdc, alice, 100e6);
        es[1] = _transfer(usdc, bob, 200e6);
        (bool ok, bytes memory reason) = _operatorBatch(operator, es);
        if (!ok) _bubble(reason);
        assertEq(usdc.balanceOf(alice), 100e6);
        assertEq(usdc.balanceOf(bob), 200e6);
        assertEq(usdc.balanceOf(address(safe)), SAFE_USDC - 300e6);
    }

    function test_S01_allow_dailyBudgetThenRefill() public {
        for (uint256 i; i < 3; i++) {
            (bool ok, bytes memory reason) = _operatorExec(operator, _transfer(usdc, alice, MAX_PER_TX));
            if (!ok) _bubble(reason);
        }
        assertEq(usdc.balanceOf(alice), MAX_PER_DAY);
        _assertBlocked(_transfer(usdc, alice, 1e6)); // budget exhausted
        vm.warp(block.timestamp + 1 days + 1);
        (bool ok2,) = _operatorExec(operator, _transfer(usdc, alice, MAX_PER_TX));
        assertTrue(ok2, "budget did not refill");
        assertEq(usdc.balanceOf(alice), MAX_PER_DAY + MAX_PER_TX);
    }

    /*//////////////////////////////////////////////////////////////
                        PROHIBITED OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_S02_block_unauthorizedDestination() public {
        _assertProhibited(_call(address(unauthorized), abi.encodeCall(UnauthorizedTarget.poke, (1))));
    }

    function test_S03_block_unauthorizedSelector() public {
        _assertProhibited(_call(address(usdc), abi.encodeCall(TestToken.burn, (1000e6))));
    }

    function test_S04_block_unauthorizedRecipient() public {
        _assertProhibited(_transfer(usdc, attacker, 100e6));
    }

    function test_S04_block_amountAboveMandate_byOperatorLayer() public {
        _assertBlocked(_transfer(usdc, alice, MAX_PER_TX + 1));
    }

    function test_S04_block_nonZeroValueOnAuthorizedCall() public {
        Exec memory e = _transfer(usdc, alice, 1e6);
        e.value = 1;
        _assertBlocked(e);
        // The engine's ERC20TransferPolicy does not check `value`; the call still fails closed because
        // the token is not payable, and the guard's after-execution hook reverts (ModuleExecutionFailed).
        _assertModuleCompromiseBlocked(e);
    }

    function test_S05_block_directTransferOfProtectedAssets() public {
        _assertProhibited(Exec(attacker, 1 ether, "", 0)); // native ETH
        _assertProhibited(Exec(alice, 1 ether, "", 0)); // ETH, even to an allowed USDC recipient
        _assertProhibited(_transfer(bond, attacker, 1000e6)); // protected ERC-20
        _assertProhibited(_transfer(bond, alice, 1000e6));
    }

    function test_S06_block_unauthorizedTokenApproval() public {
        _assertProhibited(_call(address(usdc), abi.encodeCall(usdc.approve, (attacker, type(uint256).max))));
        _assertProhibited(_call(address(bond), abi.encodeCall(bond.approve, (attacker, type(uint256).max))));
    }

    function test_S07_block_safeOwnershipModification() public {
        _assertProhibited(_call(address(safe), abi.encodeCall(ISafe150.addOwnerWithThreshold, (attacker, 1))));
        _assertProhibited(
            _call(address(safe), abi.encodeCall(ISafe150.swapOwner, (SENTINEL, owners[0], attacker)))
        );
        _assertProhibited(_call(address(safe), abi.encodeCall(ISafe150.changeThreshold, (1))));
    }

    function test_S08_block_moduleInstallationAndRemoval() public {
        _assertProhibited(_call(address(safe), abi.encodeCall(ISafe150.enableModule, (attacker))));
        address m = _operatorModule();
        _assertProhibited(_call(address(safe), abi.encodeCall(ISafe150.disableModule, (_prevModule(m), m))));
    }

    function test_S09_block_guardReplacementAndRemoval() public {
        _assertProhibited(_call(address(safe), abi.encodeCall(ISafe150.setGuard, (address(0)))));
        _assertProhibited(_call(address(safe), abi.encodeCall(ISafe150.setGuard, (attacker))));
        _assertProhibited(_call(address(safe), abi.encodeCall(ISafe150.setModuleGuard, (address(0)))));
    }

    function test_S10_block_policyConfigurationModification() public {
        PolicyConfig[] memory evil = new PolicyConfig[](1);
        evil[0] = PolicyConfig(address(0), bytes4(0), 0, ownerOnlyPolicy, ""); // a CALL fallback
        bytes32 root = keccak256(abi.encode(evil));
        _assertProhibited(_call(address(guard), abi.encodeCall(IPolicyGuard.requestConfiguration, (root))));
        _assertProhibited(_call(address(guard), abi.encodeCall(IPolicyGuard.applyConfiguration, (evil))));
        _assertProhibited(_call(address(guard), abi.encodeCall(IPolicyGuard.configureImmediately, (evil))));
        assertEq(guard.rootConfigured(address(safe), root), 0, "root was requested for the Safe");
    }

    function test_S10_operatorCallingGuardDirectly_onlyTouchesItsOwnNamespace() public {
        PolicyConfig[] memory evil = new PolicyConfig[](1);
        evil[0] = PolicyConfig(address(0), bytes4(0), 0, ownerOnlyPolicy, "");
        Effects memory before = _effects();
        vm.prank(operator.addr);
        guard.configureImmediately(evil); // succeeds - for the operator's own address
        (, address p) = guard.getPolicy(operator.addr, attacker, "", 0);
        assertEq(p, ownerOnlyPolicy);
        (, address q) = guard.getPolicy(address(safe), attacker, "", 0);
        assertEq(q, address(0), "Safe's policies changed");
        _assertNoEffects(before);
    }

    function test_S11_block_arbitraryDelegatecall() public {
        _assertProhibited(Exec(address(drainer), 0, abi.encodeCall(Drainer.drain, (payable(attacker))), 1));
        // delegatecall to the authorized token: different access key (operation bit) -> no policy
        _assertProhibited(Exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 1e6)), 1));
    }

    function test_S12_block_unauthorizedMultiSend() public {
        Exec[] memory es = new Exec[](2);
        es[0] = _transfer(usdc, alice, 100e6); // allowed on its own
        es[1] = _transfer(usdc, attacker, 100e6);
        _assertProhibitedBatch(es); // atomically: alice receives nothing either

        es[1] = Exec(attacker, 1 ether, "", 0);
        _assertProhibitedBatch(es);

        es[1] = _call(address(safe), abi.encodeCall(ISafe150.addOwnerWithThreshold, (attacker, 1)));
        _assertProhibitedBatch(es);
    }

    function test_S12_block_multiSendWithDelegatecallSubTransaction() public {
        Exec[] memory es = new Exec[](1);
        es[0] = Exec(address(drainer), 0, abi.encodeCall(Drainer.drain, (payable(attacker))), 1);
        // As a direct MultiSend (the Policy Engine's MultiSendPolicy re-checks the DELEGATECALL sub-tx).
        _assertModuleCompromiseBlocked(_multiSendExec(es));
    }

    function test_S13_block_revokedOperator() public {
        Exec memory r = _revokeOperatorTx(operator.addr);
        _ownerExecOrFail(r.to, r.value, r.data, r.operation); // a Policy-Engine-checked owner tx
        _assertBlocked(_transfer(usdc, alice, 1e6));
    }

    function test_S13_block_unregisteredKey() public {
        Key memory stranger = _newKey("stranger");
        Effects memory before = _effects();
        (bool ok,) = _operatorExec(stranger, _transfer(usdc, alice, 1e6));
        assertFalse(ok);
        _assertNoEffects(before);
    }

    function test_S14_allow_operatorRotation_sameSafe() public {
        address safeBefore = address(safe);
        bytes32 codeBefore = address(safe).codehash;
        Key memory next = _newKey("operator2");

        _rotate(operator, next); // ONE owner tx through MultiSendPolicy + OwnerOnlyPolicy

        (bool ok, bytes memory reason) = _operatorExec(next, _transfer(usdc, bob, 50e6));
        if (!ok) _bubble(reason);
        assertEq(usdc.balanceOf(bob), 50e6);
        Effects memory before = _effects();
        (bool oldOk,) = _operatorExec(operator, _transfer(usdc, alice, 1e6));
        assertFalse(oldOk, "old key still works");
        _assertNoEffects(before);
        assertEq(address(safe), safeBefore);
        assertEq(address(safe).codehash, codeBefore);
        assertEq(vm.load(address(safe), MODULE_GUARD_SLOT), bytes32(uint256(uint160(address(guard)))));
    }

    function test_S15_ownerRecovery_requiresIncreasedThreshold() public {
        address newOwner = makeAddr("recoveredOwner");
        address lost = safe.getOwners()[0];
        bytes memory data = abi.encodeCall(ISafe150.swapOwner, (SENTINEL, lost, newOwner));

        // Regular 3-of-5 owner tx is not enough for this access selector.
        (bool ok, bytes memory reason) = _ownerExec(address(safe), 0, data, 0);
        assertFalse(ok);
        assertTrue(_isPolicyEngineDenial(reason));
        assertTrue(safe.isOwner(lost));

        // 4-of-5, passed to IncreasedThresholdPolicy as policy context.
        bytes memory four = _ownerSignatures(address(safe), 0, data, 0, 4);
        (ok, reason) = _ownerExecWith(address(safe), 0, data, 0, _withPolicyContext(four, four));
        if (!ok) _bubble(reason);
        assertTrue(safe.isOwner(newOwner));
        assertFalse(safe.isOwner(lost));
        assertEq(safe.getThreshold(), THRESHOLD);
    }

    function test_S16_block_directModuleAndOwnerEntrypoints() public {
        Effects memory before = _effects();
        // The operator key is neither a Safe module nor an owner.
        vm.prank(operator.addr);
        (bool ok,) = address(safe)
            .call(abi.encodeCall(ISafe150.execTransactionFromModule, (attacker, 1 ether, "", uint8(0))));
        assertFalse(ok, "operator is a Safe module");

        bytes32 h = safe.getTransactionHash(
            attacker, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
        bytes memory sig = _signDigest(operator, h);
        bytes memory sigs = abi.encodePacked(sig, sig, sig);
        vm.prank(operator.addr);
        (ok,) = address(safe)
            .call(
                abi.encodeCall(
                    Safe.execTransaction,
                    (
                        attacker,
                        1 ether,
                        "",
                        Enum.Operation.Call,
                        0,
                        0,
                        0,
                        address(0),
                        payable(address(0)),
                        sigs
                    )
                )
            );
        assertFalse(ok, "operator signature accepted as owner signature");
        _assertNoEffects(before);
    }

    function test_S17_ownerTransactionsAreAlsoPolicyChecked() public {
        // The engine is a uniform floor: the owners themselves cannot do what no policy allows.
        Effects memory before = _effects();
        (bool ok, bytes memory reason) =
            _ownerExec(address(usdc), 0, abi.encodeCall(usdc.transfer, (attacker, 1e6)), 0);
        assertFalse(ok);
        assertTrue(_isPolicyEngineDenial(reason));
        (ok, reason) = _ownerExec(address(safe), 0, abi.encodeCall(ISafe150.setGuard, (address(0))), 0);
        assertFalse(ok);
        assertEq(reason, _accessDenied(address(0)));
        _assertNoEffects(before);

        (ok, reason) = _ownerExec(address(usdc), 0, abi.encodeCall(usdc.transfer, (alice, 5000e6)), 0);
        if (!ok) _bubble(reason);
        assertEq(usdc.balanceOf(alice), 5000e6); // no amount cap at the floor: owners are not operators
    }

    function test_S18_block_nestedExecution() public {
        // Re-entering the account's own ERC-7579 execution entrypoint (the Safe calling itself).
        bytes memory inner = abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(attacker, 1 ether, ""))
        );
        _assertProhibited(_call(address(safe), inner));
        // Re-entering the Safe's module entrypoint from the Safe.
        _assertProhibited(
            _call(
                address(safe),
                abi.encodeCall(ISafe150.execTransactionFromModule, (attacker, 1 ether, "", uint8(0)))
            )
        );
        // A MultiSend reached by CALL (not DELEGATECALL) and a batch nested inside a batch.
        Exec[] memory leaf = new Exec[](1);
        leaf[0] = _transfer(usdc, alice, 1e6);
        Exec memory nested = _multiSendExec(leaf);
        nested.operation = 0;
        _assertProhibited(nested);
        Exec[] memory outer = new Exec[](2);
        outer[0] = _transfer(usdc, alice, 1e6);
        outer[1] = _batchAsModuleTx(leaf);
        outer[1].operation = 0; // inner batches can only be CALLs
        _assertProhibitedBatch(outer);
    }

    function test_S19_block_fallbackHandlerReplacement() public {
        _assertProhibited(_call(address(safe), abi.encodeCall(ISafe150.setFallbackHandler, (attacker))));
    }

    function test_S20_block_privilegeEscalationThroughOperatorFramework() public {
        // The operator tries to give the attacker operator rights through its own execution path.
        _assertProhibited(_registerOperatorTx(attacker));
    }

    /*//////////////////////////////////////////////////////////////
                  WHAT THE POLICY ENGINE DOES NOT DO
    //////////////////////////////////////////////////////////////*/

    /// @dev Verified limit of the floor: the engine's ERC20TransferPolicy restricts recipients, not
    ///      amounts. Per-transaction and per-day caps exist only in the operator layer, so a fully
    ///      compromised operator MODULE could pay an allowed recipient any amount.
    function test_S22_finding_policyEngineDoesNotCapAmounts() public {
        (bool ok, bytes memory reason) = _asModule(_transfer(usdc, alice, 50_000e6));
        if (!ok) _bubble(reason);
        assertEq(usdc.balanceOf(alice), 50_000e6);
    }

    /// @dev Operational cost of the floor: a new destination must also be allowed by the engine,
    ///      and once the guards are installed every engine change waits out POLICY_DELAY.
    function test_S21_newDestinationRequiresPolicyEngineDelay() public {
        PolicyConfig[] memory cfg = new PolicyConfig[](1);
        cfg[0] = PolicyConfig(address(unauthorized), UnauthorizedTarget.poke.selector, 0, ownerOnlyPolicy, "");
        bytes32 root = keccak256(abi.encode(cfg));

        (bool ok, bytes memory reason) =
            _ownerExec(address(guard), 0, abi.encodeCall(IPolicyGuard.configureImmediately, (cfg)), 0);
        assertFalse(ok, "configureImmediately after installation");
        _ownerExecOrFail(address(guard), 0, abi.encodeCall(IPolicyGuard.requestConfiguration, (root)), 0);
        (ok, reason) =
            _ownerExec(address(guard), 0, abi.encodeCall(IPolicyGuard.applyConfiguration, (cfg)), 0);
        assertFalse(ok, "applied before the delay");
        assertEq(bytes4(reason), bytes4(keccak256("RootConfigurationPending()")));

        vm.warp(block.timestamp + POLICY_DELAY);
        _ownerExecOrFail(address(guard), 0, abi.encodeCall(IPolicyGuard.applyConfiguration, (cfg)), 0);
        (, address p) = guard.getPolicy(
            address(safe), address(unauthorized), abi.encodeCall(UnauthorizedTarget.poke, (1)), 0
        );
        assertEq(p, ownerOnlyPolicy);
    }

    /*//////////////////////////////////////////////////////////////
                      THE INVARIANT (fuzzed)
    //////////////////////////////////////////////////////////////*/

    /// @notice Whatever the operator module asks the Safe to do, it only takes effect if it matches
    ///         an access key configured in the Policy Engine (and that key's policy accepted it).
    function testFuzz_moduleCannotBypassPolicyEngine(
        uint8 toSeed,
        uint8 selSeed,
        bytes4 rawSelector,
        uint8 recipientSeed,
        uint96 amount,
        uint64 value,
        bool delegate
    ) public {
        address[9] memory tos = [
            address(usdc),
            address(bond),
            address(safe),
            address(guard),
            address(multiSend),
            address(unauthorized),
            address(drainer),
            attacker,
            _operatorModule()
        ];
        bytes4[8] memory sels = [
            usdc.transfer.selector,
            usdc.approve.selector,
            TestToken.burn.selector,
            ISafe150.addOwnerWithThreshold.selector,
            ISafe150.enableModule.selector,
            ISafe150.setGuard.selector,
            IPolicyGuard.requestConfiguration.selector,
            rawSelector
        ];
        address[3] memory recipients = [alice, attacker, address(safe)];
        Exec memory e = Exec(
            tos[toSeed % tos.length],
            value % 2 == 0 ? 0 : uint256(value) % 1 ether,
            abi.encodePacked(
                sels[selSeed % sels.length], abi.encode(recipients[recipientSeed % 3], uint256(amount))
            ),
            delegate ? 1 : 0
        );

        uint256 snap = vm.snapshotState();
        (bool ok,) = _asModule(e);
        vm.revertToState(snap);
        if (!ok) return;

        // It went through: the exact access key must have a configured policy...
        (, address policy) = guard.getPolicy(address(safe), e.to, e.data, e.operation);
        assertTrue(policy != address(0), "executed without a configured policy");
        // ...and for the only asset-moving key, the recipient must be on the allowlist.
        if (e.to == address(usdc) && bytes4(e.data) == usdc.transfer.selector) {
            assertEq(recipients[recipientSeed % 3], alice, "transfer to a non-allowlisted recipient");
        }
    }
}
