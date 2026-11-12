// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Safe v1.5.0: the first release with a module guard, which Safe Policy Engine requires.
import { Safe } from "@safe-global/safe-smart-account/contracts/Safe.sol";
import { SafeProxyFactory } from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { MultiSendCallOnly } from "@safe-global/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";
import {
    CompatibilityFallbackHandler
} from "@safe-global/safe-smart-account/contracts/handler/CompatibilityFallbackHandler.sol";
import { Enum } from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";

// Zodiac Roles v2.1.1 (LGPL-3.0-only) and Zodiac core 3.4.1
import { Roles } from "zodiac-roles/Roles.sol";
import { ExecutionOptions } from "zodiac-roles/Types.sol";
import { Enum as ZodiacEnum } from "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import { ModuleProxyFactory } from "@gnosis.pm/zodiac/contracts/factory/ModuleProxyFactory.sol";

import { OwnerOnlyPolicy } from "src/sentinel/OwnerOnlyPolicy.sol";
import { ERC20ApproveCapPolicy } from "src/sentinel/ERC20ApproveCapPolicy.sol";
import { SentinelSetup, EngineEntry, OwnerCall } from "script/sentinel/SentinelSetup.sol";

/// @notice 6-decimal fee token (USDC.e stand-in) with open minting.
contract FeeToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) { }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev ABI of `SentinelOracle.ConstructorParams` (safenet @ c355af1).
struct OracleParams {
    address arbitrator;
    address governance;
    address protocolFundsReceiver;
    address proposer;
    address feeToken;
    uint96 requestFee;
    uint32 initialBondMultiplier;
    uint32 initialSlashingMultiplier;
    uint24 initialDaoFeeShare;
    uint32 commitWindow;
    uint32 revealWindow;
    uint32 governanceDelay;
    uint32 arbitrationTimeout;
    string initialCharterEns;
}

/// @dev The parts of Safenet's SentinelOracle the tests call (deployed from its artifact).
interface ISentinelOracle {
    function postRequest(bytes32 requestId, address sponsor, bytes calldata) external;
    function commit(bytes32 requestId, bytes32 commitHash) external;
    function reveal(bytes32 requestId, bool approve, bytes32 salt, string calldata reason) external;
    function finalize(bytes32 requestId) external;
    function claim(bytes32 requestId) external;
    function timeoutArbitration(bytes32 requestId) external;
    function addSentinel(address sentinel) external;
    function removeSentinel(address sentinel) external;
    function applyFee() external;
    function hashCommitment(
        address sentinel,
        bytes32 requestId,
        bool approve,
        bytes32 salt,
        string calldata reason
    ) external view returns (bytes32);
}

/// @dev Safe v1.5.0 admin surface.
interface ISafeAdmin {
    function addOwnerWithThreshold(address owner, uint256 threshold) external;
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

interface IPolicyGuard {
    function getPolicy(address safe, address to, bytes calldata data, uint8 operation)
        external
        view
        returns (uint256 access, address policy);
}

/**
 * @notice Safenet sentinel run from a Safe; the server holds only a Zodiac Roles SENTINEL key.
 *
 *   Safe v1.5.0, 3-of-5 owners   = the registered sentinel; holds USDC.e
 *   Roles, role SENTINEL         = the server key: approve(oracle, <= 800 USDC.e) and the five oracle calls
 *   SafePolicyGuard              = tx guard + module guard, default-deny, entries from SentinelSetup
 *
 * Everything is real upstream code (Safe, Roles, Policy Engine, SentinelOracle); only the fee token is a
 * stand-in. Standalone: nothing here is shared with the operator-key / session-key comparison.
 */
abstract contract SentinelSafeBase is Test {
    address internal constant SENTINEL_LIST = address(0x1); // Safe's linked-list sentinel, not Safenet's
    uint256 internal constant OWNER_COUNT = 5;
    uint256 internal constant THRESHOLD = 3;
    uint256 internal constant POLICY_DELAY = 1 days;
    uint256 internal constant POLICY_EXPIRY = 7 days;

    uint256 internal constant MAX_BOND = 800e6; // 800 USDC.e

    // Oracle parameters: identical to the production SentinelOracle on Gnosis Chain
    // (0x4F61B8832978e83b80D69551AEf07557DBE41d03): fee 0.40 USDC.e, bond 2000 x fee = 800 USDC.e.
    uint96 internal constant REQUEST_FEE = 0.4e6;
    uint32 internal constant BOND_MULTIPLIER = 2000;
    uint32 internal constant SLASHING_MULTIPLIER = 1;
    uint256 internal constant BOND = uint256(REQUEST_FEE) * BOND_MULTIPLIER;
    uint32 internal constant COMMIT_WINDOW = 6;
    uint32 internal constant REVEAL_WINDOW = 6;
    uint32 internal constant GOVERNANCE_DELAY = 51_840; // ~3 days
    uint32 internal constant ARBITRATION_TIMEOUT = 483_840; // ~28 days

    uint256 internal constant SAFE_USDC = 100_000e6;
    uint256 internal constant SAFE_ETH = 1 ether;

    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant MODULE_GUARD_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    bytes32 internal constant FALLBACK_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    address internal constant EIP2470_FACTORY = 0xce0042B868300000d44A59004Da54A005ffdcf9f;
    bytes internal constant EIP2470_RUNTIME =
        hex"6080604052348015600f57600080fd5b506004361060285760003560e01c80634af63f0214602d575b600080fd5b60cf60048036036040811015604157600080fd5b810190602081018135640100000000811115605b57600080fd5b820183602082011115606c57600080fd5b80359060200191846001830284011164010000000083111715608d57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929550509135925060eb915050565b604080516001600160a01b039092168252519081900360200190f35b6000818351602085016000f5939250505056fea26469706673582212206b44f8a82cb6b156bfcc3dc6aadd6df4eefd204bc928a4397fd15dacf6d5320564736f6c63430006020033";

    struct Key {
        address addr;
        uint256 pk;
    }

    struct Exec {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
    }

    // Infrastructure (fresh locally; the canonical deployments on a fork)
    Safe internal safeSingleton;
    SafeProxyFactory internal safeFactory;
    address internal fallbackHandler;
    ModuleProxyFactory internal moduleFactory;

    Safe internal safe;
    MultiSendCallOnly internal multiSend;
    Roles internal roles;
    IPolicyGuard internal guard;
    SentinelSetup.Policies internal pol;

    FeeToken internal usdce;
    ISentinelOracle internal oracle;

    uint256[] internal ownerKeys;
    Key internal server; // the SENTINEL role key
    Key internal peer; // an ordinary EOA sentinel
    address internal treasury;
    address internal attacker;
    address internal governance;
    address internal proposer;
    address internal sponsor;
    address internal arbitrator;
    address internal fundsReceiver;

    function _pe(string memory name) internal pure returns (string memory) {
        return string.concat("out/", name, ".sol/", name, ".json");
    }

    /*//////////////////////////////////////////////////////////////
               ENVIRONMENT HOOKS (local by default, see SentinelSafeFork)
    //////////////////////////////////////////////////////////////*/

    /// @dev Safe v1.5.0 singleton, proxy factory, MultiSendCallOnly, fallback handler; Zodiac factory.
    function _deployInfra() internal virtual {
        safeSingleton = new Safe();
        safeFactory = new SafeProxyFactory();
        multiSend = new MultiSendCallOnly();
        fallbackHandler = address(new CompatibilityFallbackHandler());
        if (EIP2470_FACTORY.code.length == 0) vm.etch(EIP2470_FACTORY, EIP2470_RUNTIME);
        moduleFactory = new ModuleProxyFactory();
    }

    /// @dev The fee token and its SentinelOracle (sets `usdce`, `oracle`, and the Safenet roles).
    function _deployMarket() internal virtual {
        usdce = new FeeToken("Bridged USDC", "USDC.e");
        oracle = _deployOracle(address(usdce));
    }

    function _fund(address token, address to, uint256 amount) internal virtual {
        FeeToken(token).mint(to, amount);
    }

    function setUp() public virtual {
        _deployInfra();

        guard = IPolicyGuard(vm.deployCode(_pe("SafePolicyGuard"), abi.encode(POLICY_DELAY, POLICY_EXPIRY)));
        pol = SentinelSetup.Policies({
            approveCap: address(new ERC20ApproveCapPolicy()),
            allow: vm.deployCode(_pe("AllowPolicy")),
            erc20Transfer: vm.deployCode(_pe("ERC20TransferPolicy")),
            increasedThreshold: vm.deployCode(_pe("IncreasedThresholdPolicy")),
            ownerOnly: address(new OwnerOnlyPolicy())
        });

        address[] memory owners = new address[](OWNER_COUNT);
        for (uint256 i; i < OWNER_COUNT; i++) {
            (address o, uint256 k) = makeAddrAndKey(string.concat("owner", vm.toString(i)));
            owners[i] = o;
            ownerKeys.push(k);
        }
        server = _newKey("serverKey");
        peer = _newKey("peerSentinel");
        treasury = makeAddr("treasury");
        attacker = makeAddr("attacker");
        governance = makeAddr("governance");
        proposer = makeAddr("proposer");
        sponsor = makeAddr("sponsor");
        arbitrator = makeAddr("arbitrator");
        fundsReceiver = makeAddr("fundsReceiver");

        safe = Safe(
            payable(address(
                    safeFactory.createProxyWithNonce(
                        address(safeSingleton),
                        abi.encodeCall(
                            Safe.setup,
                            (
                                owners,
                                THRESHOLD,
                                address(0),
                                "",
                                fallbackHandler,
                                address(0),
                                0,
                                payable(address(0))
                            )
                        ),
                        uint256(keccak256("intentguard.sentinel-safe"))
                    )
                ))
        );

        // Roles v2.1.1: a mastercopy (once per chain) and one minimal proxy for this Safe
        // (owner = avatar = target = the Safe).
        Roles mastercopy = new Roles(address(0xdead), address(0xdead), address(0xdead));
        roles = Roles(
            moduleFactory.deployModule(
                address(mastercopy),
                abi.encodeCall(Roles.setUp, (abi.encode(address(safe), address(safe), address(safe)))),
                0
            )
        );

        _deployMarket();
        _prepareCounterparties(address(usdce), oracle);
        _fund(address(usdce), address(safe), SAFE_USDC);
        vm.deal(address(safe), SAFE_ETH);

        _bootstrap();
    }

    function _market() internal view returns (SentinelSetup.Market memory) {
        return SentinelSetup.Market({ feeToken: address(usdce), oracle: address(oracle), maxBond: MAX_BOND });
    }

    /// @dev Owner transactions, in order, exactly as signed in production.
    function _bootstrap() internal virtual {
        // 1. one batch before the guard exists: enable Roles, give SENTINEL the USDC.e market, grant the key
        OwnerCall[] memory calls = new OwnerCall[](1);
        calls[0] = SentinelSetup.enableRoles(address(safe), address(roles));
        calls = SentinelSetup.concat(calls, SentinelSetup.rolesAddMarket(address(roles), _market()));
        OwnerCall[] memory assign = new OwnerCall[](1);
        assign[0] = SentinelSetup.rolesAssign(address(roles), server.addr, true);
        calls = SentinelSetup.concat(calls, assign);
        _ownerBatchOrFail(calls);

        // 2. configure the engine, 3. install it as both guards (atomically)
        _ownerExecOrFail(address(guard), 0, SentinelSetup.configureImmediately(_entries()), 0);
        _ownerBatchOrFail(SentinelSetup.installGuards(address(safe), address(guard)));
        require(vm.load(address(safe), GUARD_SLOT) == bytes32(uint256(uint160(address(guard)))), "tx guard");
        require(
            vm.load(address(safe), MODULE_GUARD_SLOT) == bytes32(uint256(uint160(address(guard)))),
            "module guard"
        );

        // Safenet governance registers the Safe (not the key) as the sentinel.
        vm.startPrank(governance);
        oracle.addSentinel(address(safe));
        oracle.addSentinel(peer.addr);
        vm.stopPrank();
        vm.roll(block.number + GOVERNANCE_DELAY);
    }

    function _entries() internal view returns (EngineEntry[] memory) {
        SentinelSetup.Market[] memory markets = new SentinelSetup.Market[](1);
        markets[0] = _market();
        return SentinelSetup.allEntries(address(safe), address(roles), treasury, markets, pol);
    }

    function _deployOracle(address feeToken) internal returns (ISentinelOracle o) {
        o = ISentinelOracle(
            vm.deployCode(
                "out/SentinelOracle.sol/SentinelOracle.json",
                abi.encode(
                    OracleParams({
                        arbitrator: arbitrator,
                        governance: governance,
                        protocolFundsReceiver: fundsReceiver,
                        proposer: proposer,
                        feeToken: feeToken,
                        requestFee: REQUEST_FEE,
                        initialBondMultiplier: BOND_MULTIPLIER,
                        initialSlashingMultiplier: SLASHING_MULTIPLIER,
                        initialDaoFeeShare: 0,
                        commitWindow: COMMIT_WINDOW,
                        revealWindow: REVEAL_WINDOW,
                        governanceDelay: GOVERNANCE_DELAY,
                        arbitrationTimeout: ARBITRATION_TIMEOUT,
                        initialCharterEns: "safenet-charter.safe.eth"
                    })
                )
            )
        );
    }

    /// @dev The sponsor (pays request fees) and the peer sentinel (an ordinary EOA) on market `o`.
    function _prepareCounterparties(address feeToken, ISentinelOracle o) internal {
        _fund(feeToken, sponsor, 100_000e6);
        _fund(feeToken, peer.addr, 100_000e6);
        vm.prank(sponsor);
        ERC20(feeToken).approve(address(o), type(uint256).max);
        vm.prank(peer.addr);
        ERC20(feeToken).approve(address(o), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                           OWNER TRANSACTIONS
    //////////////////////////////////////////////////////////////*/

    function _ownerExec(address to, uint256 value, bytes memory data, uint8 op)
        internal
        returns (bool ok, bytes memory reason)
    {
        bytes32 h = safe.getTransactionHash(
            to, value, data, Enum.Operation(op), 0, 0, 0, address(0), address(0), safe.nonce()
        );
        uint256[] memory keys = _sortedOwnerKeys();
        bytes memory sigs;
        for (uint256 i; i < THRESHOLD; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            sigs = abi.encodePacked(sigs, r, s, v);
        }
        (ok, reason) = address(safe)
            .call(
                abi.encodeCall(
                    Safe.execTransaction,
                    (to, value, data, Enum.Operation(op), 0, 0, 0, address(0), payable(address(0)), sigs)
                )
            );
    }

    function _ownerExecOrFail(address to, uint256 value, bytes memory data, uint8 op) internal {
        (bool ok, bytes memory reason) = _ownerExec(to, value, data, op);
        if (!ok) _bubble(reason);
    }

    function _ownerCallOrFail(OwnerCall memory c) internal {
        _ownerExecOrFail(c.to, 0, c.data, 0);
    }

    function _ownerBatch(OwnerCall[] memory calls) internal returns (bool, bytes memory) {
        return _ownerExec(
            address(multiSend),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (SentinelSetup.toMultiSend(calls))),
            1
        );
    }

    function _ownerBatchOrFail(OwnerCall[] memory calls) internal {
        (bool ok, bytes memory reason) = _ownerBatch(calls);
        if (!ok) _bubble(reason);
    }

    function _sortedOwnerKeys() internal view returns (uint256[] memory keys) {
        keys = ownerKeys;
        for (uint256 i; i < keys.length; i++) {
            for (uint256 j = i + 1; j < keys.length; j++) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          WHAT THE SERVER SENDS
    //////////////////////////////////////////////////////////////*/

    /// @dev From key `k` to Roles, wrapping one Safe execution. Never reverts.
    function _send(Key memory k, Exec memory e) internal returns (bool ok, bytes memory reason) {
        vm.prank(k.addr);
        (ok, reason) = address(roles)
            .call(
                abi.encodeCall(
                    Roles.execTransactionWithRole,
                    (e.to, e.value, e.data, ZodiacEnum.Operation(e.operation), SentinelSetup.ROLE, true)
                )
            );
    }

    function _send(Key memory k, address to, bytes memory data)
        internal
        returns (bool ok, bytes memory reason)
    {
        // Exactly the bytes SentinelSetup.wrap documents for the server.
        vm.prank(k.addr);
        (ok, reason) = address(roles).call(SentinelSetup.wrap(to, data));
    }

    function _sendOrFail(address to, bytes memory data) internal {
        (bool ok, bytes memory reason) = _send(server, to, data);
        if (!ok) _bubble(reason);
    }

    /// @dev Module compromise: Roles itself asks the Safe for `e`. Only the Policy Engine stands between.
    function _asModule(Exec memory e) internal returns (bool ok, bytes memory reason) {
        vm.prank(address(roles));
        (ok, reason) = address(safe)
            .call(abi.encodeCall(ISafeAdmin.execTransactionFromModule, (e.to, e.value, e.data, e.operation)));
        if (ok) ok = abi.decode(reason, (bool));
    }

    /// @dev Misconfiguration: Roles opened for everything on `target` (made as the Safe, bypassing the guard).
    function _openRoles(address target) internal {
        vm.prank(address(safe));
        roles.allowTarget(SentinelSetup.ROLE, target, ExecutionOptions.Both);
    }

    /*//////////////////////////////////////////////////////////////
                             ORACLE FLOW
    //////////////////////////////////////////////////////////////*/

    function _id(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode("request", i));
    }

    function _post(ISentinelOracle o, bytes32 id) internal {
        vm.prank(proposer);
        o.postRequest(id, sponsor, "");
    }

    /// @dev approve(oracle, BOND) then commit, as the sentinel service sends them. The hash names the SAFE.
    function _commitAsSafe(ISentinelOracle o, address token, bytes32 id, bool approve, bytes32 salt)
        internal
    {
        _sendOrFail(token, abi.encodeCall(ERC20.approve, (address(o), BOND)));
        _sendOrFail(
            address(o),
            abi.encodeCall(
                ISentinelOracle.commit, (id, o.hashCommitment(address(safe), id, approve, salt, ""))
            )
        );
    }

    function _revealAsSafe(ISentinelOracle o, bytes32 id, bool approve, bytes32 salt) internal {
        _sendOrFail(address(o), abi.encodeCall(ISentinelOracle.reveal, (id, approve, salt, "")));
    }

    function _commitAs(address who, bytes32 id, bool approve, bytes32 salt) internal {
        bytes32 h = oracle.hashCommitment(who, id, approve, salt, "");
        vm.prank(who);
        oracle.commit(id, h);
    }

    function _revealAs(address who, bytes32 id, bool approve, bytes32 salt) internal {
        vm.prank(who);
        oracle.reveal(id, approve, salt, "");
    }

    function _toRevealWindow() internal {
        vm.roll(block.number + COMMIT_WINDOW + 1);
    }

    function _pastRevealDeadline() internal {
        vm.roll(block.number + REVEAL_WINDOW + 1);
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
        uint256 safeUsdc;
        uint256 safeEth;
        uint256 attackerUsdc;
        uint256 attackerEth;
        uint256 allowanceAttacker;
        uint256 allowanceOracle;
        address approvePolicy;
    }

    function _effects() internal view returns (Effects memory e) {
        e.owners = safe.getOwners();
        e.threshold = safe.getThreshold();
        (e.modules,) = safe.getModulesPaginated(SENTINEL_LIST, 10);
        e.guardSlot = vm.load(address(safe), GUARD_SLOT);
        e.moduleGuardSlot = vm.load(address(safe), MODULE_GUARD_SLOT);
        e.fallbackSlot = vm.load(address(safe), FALLBACK_SLOT);
        e.safeUsdc = usdce.balanceOf(address(safe));
        e.safeEth = address(safe).balance;
        e.attackerUsdc = usdce.balanceOf(attacker);
        e.attackerEth = attacker.balance;
        e.allowanceAttacker = usdce.allowance(address(safe), attacker);
        e.allowanceOracle = usdce.allowance(address(safe), address(oracle));
        (, e.approvePolicy) = guard.getPolicy(
            address(safe), address(usdce), abi.encodeCall(ERC20.approve, (address(oracle), 1)), 0
        );
    }

    function _assertNoEffects(Effects memory a, string memory label) internal view {
        Effects memory b = _effects();
        assertEq(abi.encode(a.owners), abi.encode(b.owners), string.concat(label, ": owners"));
        assertEq(a.threshold, b.threshold, string.concat(label, ": threshold"));
        assertEq(abi.encode(a.modules), abi.encode(b.modules), string.concat(label, ": modules"));
        assertEq(a.guardSlot, b.guardSlot, string.concat(label, ": tx guard"));
        assertEq(a.moduleGuardSlot, b.moduleGuardSlot, string.concat(label, ": module guard"));
        assertEq(a.fallbackSlot, b.fallbackSlot, string.concat(label, ": fallback handler"));
        assertEq(a.safeUsdc, b.safeUsdc, string.concat(label, ": Safe USDC.e"));
        assertEq(a.safeEth, b.safeEth, string.concat(label, ": Safe ETH"));
        assertEq(a.attackerUsdc, b.attackerUsdc, string.concat(label, ": attacker USDC.e"));
        assertEq(a.attackerEth, b.attackerEth, string.concat(label, ": attacker ETH"));
        assertEq(a.allowanceAttacker, b.allowanceAttacker, string.concat(label, ": allowance to attacker"));
        assertEq(a.allowanceOracle, b.allowanceOracle, string.concat(label, ": allowance to oracle"));
        assertEq(a.approvePolicy, b.approvePolicy, string.concat(label, ": engine entry"));
    }

    function _isEngineDenial(bytes memory reason) internal pure returns (bool) {
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

    function _newKey(string memory name) internal returns (Key memory k) {
        (k.addr, k.pk) = makeAddrAndKey(name);
    }

    function _bubble(bytes memory reason) internal pure {
        assembly {
            revert(add(reason, 32), mload(reason))
        }
    }
}
