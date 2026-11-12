// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, Vm } from "forge-std/Test.sol";

// Safe v1.5.0: the first release with a module guard, which Safe Policy Engine requires.
import { Safe } from "@safe-global/safe-smart-account/contracts/Safe.sol";
import { SafeProxyFactory } from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { MultiSendCallOnly } from "@safe-global/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";
import {
    CompatibilityFallbackHandler
} from "@safe-global/safe-smart-account/contracts/handler/CompatibilityFallbackHandler.sol";
import { Enum } from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";

import { OwnerOnlyPolicy } from "src/policies/engine/OwnerOnlyPolicy.sol";
import { OperatorKeySetup, PolicyConfig, RecipientData } from "script/lib/OperatorKeySetup.sol";
import { TestToken, UnauthorizedTarget, Drainer } from "./OperatorKeyFixtures.sol";

/// @dev Safe v1.5.0 admin surface (inherited functions are not reachable via `Safe.x` in encodeCall).
interface ISafe150 {
    function addOwnerWithThreshold(address owner, uint256 threshold) external;
    function swapOwner(address prevOwner, address oldOwner, address newOwner) external;
    function changeThreshold(uint256 threshold) external;
    function enableModule(address module) external;
    function disableModule(address prevModule, address module) external;
    function setGuard(address guard) external;
    function setModuleGuard(address guard) external;
    function setFallbackHandler(address handler) external;
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool);
}

/// @dev The parts of SafePolicyGuard the tests call (implementation is deployed from its artifact).
interface IPolicyGuard {
    function configureImmediately(PolicyConfig[] calldata configurations) external;
    function requestConfiguration(bytes32 configureRoot) external;
    function applyConfiguration(PolicyConfig[] calldata configurations) external;
    function invalidateRoot(bytes32 configureRoot) external;
    function getPolicy(address safe, address to, bytes calldata data, uint8 operation)
        external
        view
        returns (uint256 access, address policy);
    function rootConfigured(address safe, bytes32 root) external view returns (uint256);
}

/**
 * @notice Common ground for both operator-key architectures. Everything here is shared, identical,
 *         and real (no mocked policy results). Calldata comes from script/lib/OperatorKeySetup.sol,
 *         the same builders the deployment script uses:
 *
 *   Safe v1.5.0, 3-of-5 owners, holds ETH, USDC (operational) and BOND (protected)
 *   SafePolicyGuard installed as BOTH transaction guard and module guard, default-deny, with:
 *     USDC.transfer           CALL          ERC20TransferPolicy   recipients {alice, bob}
 *     MultiSendCallOnly       DELEGATECALL  MultiSendPolicy       (each sub-transaction re-checked)
 *     Safe.swapOwner          CALL          IncreasedThresholdPolicy (4 of 5 signatures)
 *     Safe.disableModule      CALL          OwnerOnlyPolicy       (emergency kill switch)
 *     + the architecture's own entries (`_architecturePolicies`)
 *
 * An architecture plugs in through the virtual hooks at the bottom: how it is deployed and
 * attached, how its operator key executes, and how owners register / revoke operators.
 */
abstract contract OperatorKeyBase is Test {
    address internal constant SENTINEL = address(0x1);
    uint256 internal constant OWNER_COUNT = 5;
    uint256 internal constant THRESHOLD = 3;
    uint256 internal constant POLICY_DELAY = 1 days;
    uint256 internal constant POLICY_EXPIRY = 7 days;

    // The operator's mandate (identical in both architectures)
    uint256 internal constant MAX_PER_TX = 1000e6; // USDC
    uint256 internal constant MAX_PER_DAY = 3000e6; // USDC
    uint48 internal constant OPERATOR_TTL = 30 days; // only expressible in Smart Sessions (see docs)

    uint256 internal constant SAFE_ETH = 100 ether;
    uint256 internal constant SAFE_USDC = 1_000_000e6;
    uint256 internal constant SAFE_BOND = 500_000e6;

    // keccak256("guard_manager.guard.address"), keccak256("module_manager.module_guard.address"),
    // keccak256("fallback_manager.handler.address")
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant MODULE_GUARD_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    bytes32 internal constant FALLBACK_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    // keccak256("SafePolicyGuard.PolicyContext.v1")
    bytes32 internal constant POLICY_CONTEXT_TYPEHASH =
        0x5aa463b48748f9162d63ae93151d31fed6a96b34cd2ae84ef33d25b0bdea62e4;

    struct Key {
        address addr;
        uint256 pk;
    }

    /// @dev One Safe-level execution: what the Safe would do, and what the Policy Engine checks.
    struct Exec {
        address to;
        uint256 value;
        bytes data;
        uint8 operation; // 0 CALL, 1 DELEGATECALL
    }

    // Safe
    Safe internal safeSingleton;
    SafeProxyFactory internal safeFactory;
    MultiSendCallOnly internal multiSend;
    CompatibilityFallbackHandler internal fallbackHandler;
    Safe internal safe;

    // Safe Policy Engine (upstream, deployed from artifacts) + OwnerOnlyPolicy (this repo)
    IPolicyGuard internal guard;
    address internal erc20TransferPolicy;
    address internal multiSendPolicy;
    address internal increasedThresholdPolicy;
    address internal allowedModulePolicy;
    address internal nativeTransferPolicy;
    address internal ownerOnlyPolicy;

    // Assets and targets
    TestToken internal usdc;
    TestToken internal bond;
    UnauthorizedTarget internal unauthorized;
    Drainer internal drainer;

    // Actors
    uint256[] internal ownerKeys;
    address[] internal owners;
    Key internal operator;
    address internal alice;
    address internal bob;
    address internal attacker;
    address payable internal relayer; // submits operator-signed payloads (relayer / bundler)

    /// @dev Gas baselines only: build the identical stack but never install the Policy Engine.
    bool internal withoutPolicyEngine;

    /// @dev Upstream Policy Engine artifact, built with its own compiler profile (see foundry.toml).
    ///      Referenced by path: forge's name-based artifact lookup does not cross compiler profiles.
    function _pe(string memory name) internal pure returns (string memory) {
        return string.concat("out/", name, ".sol/", name, ".json");
    }

    function setUp() public virtual {
        safeSingleton = new Safe();
        safeFactory = new SafeProxyFactory();
        multiSend = new MultiSendCallOnly();
        fallbackHandler = new CompatibilityFallbackHandler();

        guard = IPolicyGuard(vm.deployCode(_pe("SafePolicyGuard"), abi.encode(POLICY_DELAY, POLICY_EXPIRY)));
        erc20TransferPolicy = vm.deployCode(_pe("ERC20TransferPolicy"));
        multiSendPolicy = vm.deployCode(_pe("MultiSendPolicy"));
        increasedThresholdPolicy = vm.deployCode(_pe("IncreasedThresholdPolicy"));
        allowedModulePolicy = vm.deployCode(_pe("AllowedModulePolicy"));
        nativeTransferPolicy = vm.deployCode(_pe("NativeTransferPolicy"));
        ownerOnlyPolicy = address(new OwnerOnlyPolicy());

        usdc = new TestToken("USD Coin", "USDC");
        bond = new TestToken("Bonded collateral", "BOND");
        unauthorized = new UnauthorizedTarget();
        drainer = new Drainer();

        for (uint256 i; i < OWNER_COUNT; i++) {
            (address o, uint256 k) = makeAddrAndKey(string.concat("owner", vm.toString(i)));
            owners.push(o);
            ownerKeys.push(k);
        }
        (operator.addr, operator.pk) = makeAddrAndKey("operator");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        attacker = makeAddr("attacker");
        relayer = payable(makeAddr("relayer"));

        safe = _deploySafe();
        vm.deal(address(safe), SAFE_ETH);
        usdc.mint(address(safe), SAFE_USDC);
        bond.mint(address(safe), SAFE_BOND);

        _deployArchitecture();
        _attachArchitecture();
        _registerInitialOperator(operator.addr);
        if (!withoutPolicyEngine) _bootstrapPolicyEngine();
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY ENGINE SETUP
    //////////////////////////////////////////////////////////////*/

    function _commonPolicies() internal view returns (PolicyConfig[] memory) {
        address[] memory recipients = new address[](2);
        recipients[0] = alice;
        recipients[1] = bob;
        return OperatorKeySetup.commonPolicies(
            OperatorKeySetup.Common({
                safe: address(safe),
                token: address(usdc),
                recipients: recipients,
                multiSend: address(multiSend),
                erc20TransferPolicy: erc20TransferPolicy,
                multiSendPolicy: multiSendPolicy,
                increasedThresholdPolicy: increasedThresholdPolicy,
                ownerOnlyPolicy: ownerOnlyPolicy
            })
        );
    }

    /// @dev Configure every policy, then install BOTH guards atomically (upstream hardening sequence).
    function _bootstrapPolicyEngine() internal {
        PolicyConfig[] memory all = OperatorKeySetup.concat(_commonPolicies(), _architecturePolicies());
        _ownerExecOrFail(address(guard), 0, OperatorKeySetup.configureImmediately(all), 0);
        bytes memory txs = OperatorKeySetup.installGuards(address(safe), address(guard));
        _ownerExecOrFail(address(multiSend), 0, abi.encodeCall(MultiSendCallOnly.multiSend, (txs)), 1);

        require(vm.load(address(safe), GUARD_SLOT) == bytes32(uint256(uint160(address(guard)))), "tx guard");
        require(
            vm.load(address(safe), MODULE_GUARD_SLOT) == bytes32(uint256(uint160(address(guard)))),
            "module guard"
        );
    }

    function policyEntryCount() public view returns (uint256 common, uint256 arch) {
        return (_commonPolicies().length, _architecturePolicies().length);
    }

    /*//////////////////////////////////////////////////////////////
                           OWNER TRANSACTIONS
    //////////////////////////////////////////////////////////////*/

    function _deploySafe() internal returns (Safe) {
        bytes memory setup = abi.encodeCall(
            Safe.setup,
            (owners, THRESHOLD, address(0), "", address(fallbackHandler), address(0), 0, payable(address(0)))
        );
        return Safe(payable(address(safeFactory.createProxyWithNonce(address(safeSingleton), setup, 0))));
    }

    /// @dev Owner transaction signed by `count` owners; never reverts, returns the outcome.
    function _ownerExecWith(address to, uint256 value, bytes memory data, uint8 op, bytes memory sigs)
        internal
        returns (bool ok, bytes memory reason)
    {
        (ok, reason) = address(safe)
            .call(
                abi.encodeCall(
                    Safe.execTransaction,
                    (to, value, data, Enum.Operation(op), 0, 0, 0, address(0), payable(address(0)), sigs)
                )
            );
    }

    function _ownerExec(address to, uint256 value, bytes memory data, uint8 op)
        internal
        returns (bool ok, bytes memory reason)
    {
        return _ownerExecWith(to, value, data, op, _ownerSignatures(to, value, data, op, THRESHOLD));
    }

    function _ownerExecOrFail(address to, uint256 value, bytes memory data, uint8 op) internal {
        (bool ok, bytes memory reason) = _ownerExec(to, value, data, op);
        if (!ok) {
            assembly {
                revert(add(reason, 32), mload(reason))
            }
        }
    }

    function _ownerSignatures(address to, uint256 value, bytes memory data, uint8 op, uint256 count)
        internal
        view
        returns (bytes memory sigs)
    {
        bytes32 h = safe.getTransactionHash(
            to, value, data, Enum.Operation(op), 0, 0, 0, address(0), address(0), safe.nonce()
        );
        uint256[] memory keys = _sortedOwnerKeys();
        for (uint256 i; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            sigs = abi.encodePacked(sigs, r, s, v);
        }
    }

    function _sortedOwnerKeys() internal view returns (uint256[] memory keys) {
        keys = ownerKeys;
        for (uint256 i; i < keys.length; i++) {
            for (uint256 j = i + 1; j < keys.length; j++) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
    }

    /// @dev SignatureExtension envelope carrying policy context in the `signatures` tail.
    function _withPolicyContext(bytes memory sigs, bytes memory context)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(sigs, context, uint256(context.length), POLICY_CONTEXT_TYPEHASH);
    }

    function _multiSendTx(uint8 op, address to, uint256 value, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        return OperatorKeySetup.multiSendTx(op, to, value, data);
    }

    function _multiSendExec(Exec[] memory execs) internal view returns (Exec memory) {
        bytes memory txs;
        for (uint256 i; i < execs.length; i++) {
            txs = abi.encodePacked(
                txs, _multiSendTx(execs[i].operation, execs[i].to, execs[i].value, execs[i].data)
            );
        }
        return Exec(address(multiSend), 0, abi.encodeCall(MultiSendCallOnly.multiSend, (txs)), 1);
    }

    /*//////////////////////////////////////////////////////////////
                    OPERATOR KEYS (KMS-COMPATIBLE)
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev The ONLY place an operator key is used, in both architectures: it signs a 32-byte digest
     *      (secp256k1, no EIP-191 prefix) and returns `r || s || v`. That is exactly the operation an
     *      AWS/GCP KMS key or an HSM performs (`Sign`, MessageType=DIGEST); nothing else about the
     *      key is needed, and the key never pays gas (a relayer or bundler submits).
     */
    function _signDigest(Key memory k, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(k.pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _newKey(string memory name) internal returns (Key memory k) {
        (k.addr, k.pk) = makeAddrAndKey(name);
    }

    /*//////////////////////////////////////////////////////////////
                               EVIDENCE
    //////////////////////////////////////////////////////////////*/

    struct Effects {
        address[] owners;
        uint256 threshold;
        address[] modules;
        bytes32 guardSlot;
        bytes32 moduleGuardSlot;
        bytes32 fallbackSlot;
        bytes32 singletonSlot;
        uint256 safeEth;
        uint256 safeUsdc;
        uint256 safeBond;
        uint256 outsideEth; // alice + bob + attacker
        uint256 outsideUsdc;
        uint256 outsideBond;
        uint256 unauthorizedCalls;
        uint256 usdcAllowance; // Safe -> attacker
        address transferPolicy; // Policy Engine entry for USDC.transfer
        address setGuardPolicy; // Policy Engine entry for Safe.setGuard (must stay unset)
        bytes32 archState;
    }

    function _effects() internal view returns (Effects memory e) {
        e.owners = safe.getOwners();
        e.threshold = safe.getThreshold();
        (e.modules,) = safe.getModulesPaginated(SENTINEL, 20);
        e.guardSlot = vm.load(address(safe), GUARD_SLOT);
        e.moduleGuardSlot = vm.load(address(safe), MODULE_GUARD_SLOT);
        e.fallbackSlot = vm.load(address(safe), FALLBACK_SLOT);
        e.singletonSlot = vm.load(address(safe), bytes32(0));
        e.safeEth = address(safe).balance;
        e.safeUsdc = usdc.balanceOf(address(safe));
        e.safeBond = bond.balanceOf(address(safe));
        e.outsideEth = alice.balance + bob.balance + attacker.balance;
        e.outsideUsdc = usdc.balanceOf(alice) + usdc.balanceOf(bob) + usdc.balanceOf(attacker);
        e.outsideBond = bond.balanceOf(alice) + bond.balanceOf(bob) + bond.balanceOf(attacker);
        e.unauthorizedCalls = unauthorized.calls();
        e.usdcAllowance = usdc.allowance(address(safe), attacker);
        (, e.transferPolicy) =
            guard.getPolicy(address(safe), address(usdc), abi.encodeCall(usdc.transfer, (alice, 1)), 0);
        (, e.setGuardPolicy) =
            guard.getPolicy(address(safe), address(safe), abi.encodeCall(ISafe150.setGuard, (address(0))), 0);
        e.archState = _archState();
    }

    function _assertNoEffects(Effects memory a) internal view {
        Effects memory b = _effects();
        assertEq(abi.encode(a.owners), abi.encode(b.owners), "owners changed");
        assertEq(a.threshold, b.threshold, "threshold changed");
        assertEq(abi.encode(a.modules), abi.encode(b.modules), "modules changed");
        assertEq(a.guardSlot, b.guardSlot, "transaction guard changed");
        assertEq(a.moduleGuardSlot, b.moduleGuardSlot, "module guard changed");
        assertEq(a.fallbackSlot, b.fallbackSlot, "fallback handler changed");
        assertEq(a.singletonSlot, b.singletonSlot, "singleton changed");
        assertEq(a.safeEth, b.safeEth, "Safe ETH moved");
        assertEq(a.safeUsdc, b.safeUsdc, "Safe USDC moved");
        assertEq(a.safeBond, b.safeBond, "Safe BOND moved");
        assertEq(a.outsideEth, b.outsideEth, "ETH received outside");
        assertEq(a.outsideUsdc, b.outsideUsdc, "USDC received outside");
        assertEq(a.outsideBond, b.outsideBond, "BOND received outside");
        assertEq(a.unauthorizedCalls, b.unauthorizedCalls, "unauthorized target was called");
        assertEq(a.usdcAllowance, b.usdcAllowance, "allowance granted");
        assertEq(a.transferPolicy, b.transferPolicy, "policy entry changed");
        assertEq(a.setGuardPolicy, b.setGuardPolicy, "guard-removal policy configured");
        assertEq(a.archState, b.archState, "operator-framework state changed");
    }

    /// @dev True if `reason` is (or wraps, ABI-encoded) a Safe Policy Engine denial.
    function _isPolicyEngineDenial(bytes memory reason) internal pure returns (bool) {
        bytes4[5] memory sels = [
            bytes4(keccak256("AccessDenied(address)")),
            bytes4(keccak256("PolicyReverted(address,bytes)")),
            bytes4(keccak256("ModuleConfigurationDenied()")),
            bytes4(keccak256("GuardTargetDenied()")),
            bytes4(keccak256("ModuleExecutionFailed()"))
        ];
        for (uint256 i; i + 4 <= reason.length; i++) {
            bytes4 w;
            assembly {
                w := mload(add(add(reason, 32), i))
            }
            for (uint256 j; j < sels.length; j++) {
                if (w == sels[j]) return true;
            }
        }
        return false;
    }

    function _accessDenied(address policy) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("AccessDenied(address)", policy);
    }

    function _bubble(bytes memory reason) internal pure {
        assembly {
            revert(add(reason, 32), mload(reason))
        }
    }

    /*//////////////////////////////////////////////////////////////
                       ARCHITECTURE HOOKS (virtual)
    //////////////////////////////////////////////////////////////*/

    /// @dev Deploy the architecture's contracts (singletons and per-Safe instances).
    function _deployArchitecture() internal virtual;

    /// @dev Owner transactions, before the guards exist, that attach the framework to the Safe.
    function _attachArchitecture() internal virtual;

    /// @dev Owner transaction(s), before the guards exist, granting `op` the operator mandate.
    function _registerInitialOperator(address op) internal virtual;

    /// @dev The architecture's own Policy Engine entries (beyond `_commonPolicies`).
    function _architecturePolicies() internal view virtual returns (PolicyConfig[] memory);

    /// @dev The address the Policy Engine receives as `module` for operator executions.
    function _operatorModule() internal view virtual returns (address);

    /// @dev Operator `k` requests ONE Safe execution through the architecture's real path.
    ///      Never reverts: returns whether it took effect and, if not, why.
    function _operatorExec(Key memory k, Exec memory e)
        internal
        virtual
        returns (bool ok, bytes memory reason);

    /// @dev Operator `k` requests a batch, using the architecture's native batching.
    function _operatorBatch(Key memory k, Exec[] memory es)
        internal
        virtual
        returns (bool ok, bytes memory reason);

    /// @dev The single module transaction the architecture's module makes for a batch.
    function _batchAsModuleTx(Exec[] memory es) internal view virtual returns (Exec memory);

    /// @dev The owner-side call that grants / removes operator rights for `op` (one Safe execution).
    function _registerOperatorTx(address op) internal virtual returns (Exec memory);
    function _revokeOperatorTx(address op) internal virtual returns (Exec memory);

    /// @dev Fault injection: the operator layer is misconfigured to allow `k` everything on `target`
    ///      it can express (any selector, value, operation). Returns false if it cannot express
    ///      `operation` on `target` at all (the operator layer then still blocks structurally).
    ///      Applied as the Safe (vm.prank) to model a misconfiguration made before the guards existed.
    function _openOperatorLayer(Key memory k, address target, uint8 operation) internal virtual returns (bool);

    /// @dev Digest of the operator framework's authorization state, for no-effect assertions.
    function _archState() internal view virtual returns (bytes32);
}
