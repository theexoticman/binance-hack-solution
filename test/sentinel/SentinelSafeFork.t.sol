// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm } from "forge-std/Vm.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Safe } from "@safe-global/safe-smart-account/contracts/Safe.sol";
import { SafeProxyFactory } from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { MultiSendCallOnly } from "@safe-global/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";
import { ModuleProxyFactory } from "@gnosis.pm/zodiac/contracts/factory/ModuleProxyFactory.sol";
import { SentinelSafeTest } from "./SentinelSafe.t.sol";
import { ISentinelOracle, FeeToken } from "./SentinelSafeBase.sol";

/// @dev Safenet `SafeTransaction.T` (Operation is a two-member enum, encoded as uint8).
struct SafeTx {
    uint256 chainId;
    address safe;
    address to;
    uint256 value;
    bytes data;
    uint8 operation;
    uint256 safeTxGas;
    uint256 baseGas;
    uint256 gasPrice;
    address gasToken;
    address refundReceiver;
    uint256 nonce;
}

interface IConsensus {
    function proposeTransaction(address oracle, bytes calldata oracleData, SafeTx memory transaction)
        external
        returns (bytes32 safeTxHash);
    function attestTransaction(
        uint64 epoch,
        address oracle,
        bytes32 oracleDataHash,
        uint256 chainId,
        address safe,
        bytes32 safeTxStructHash,
        bytes32 signatureId
    ) external;
    function getCoordinator() external view returns (address);
}

interface IOracleConfig {
    function PROPOSER() external view returns (address);
    function GOVERNANCE() external view returns (address);
    function ARBITRATOR() external view returns (address);
    function FEE_TOKEN() external view returns (address);
    function COMMIT_WINDOW() external view returns (uint32);
    function REVEAL_WINDOW() external view returns (uint32);
    function GOVERNANCE_DELAY() external view returns (uint32);
    function ARBITRATION_TIMEOUT() external view returns (uint32);
    function fee() external view returns (uint96);
    function bondMultiplier() external view returns (uint32);
    function slashingMultiplier() external view returns (uint32);
    function protocolFundsReceiver() external view returns (address);
}

/**
 * @notice The whole sentinel-Safe suite, re-run on a fork of Gnosis Chain against the PRODUCTION
 *         Safenet deployment (docs/configuration.md in safe-research/safenet):
 *
 *   SentinelOracle   0x4F61B8832978e83b80D69551AEf07557DBE41d03   (fee 0.40, bond 800 USDC.e)
 *   Consensus        0xc855761D619f6002923507cE68B84d7689C2aa96
 *   USDC.e           0x2a22f9c3b484c3629090FeED35F17Ff8F88f76F0
 *   Safe v1.5.0, SafeProxyFactory, MultiSendCallOnly, CompatibilityFallbackHandler,
 *   Zodiac ModuleProxyFactory, EIP-2470 factory: the canonical Gnosis Chain deployments.
 *
 * Deployed fresh on the fork, as they would be in production: the sentinel Safe, Roles v2.1.1
 * (mastercopy + proxy), SafePolicyGuard and its policies. Production governance registers the Safe.
 * USDC.e balances come from `deal`.
 *
 * Every inherited test runs here too. The tests below add the full request lifecycle through the
 * real Consensus contract. Skipped unless GNOSIS_RPC_URL is set (FORK_BLOCK pins the block):
 *
 *   GNOSIS_RPC_URL=https://rpc.gnosischain.com forge test --mc SentinelSafeForkTest -vv
 */
contract SentinelSafeForkTest is SentinelSafeTest {
    address internal constant ORACLE = 0x4F61B8832978e83b80D69551AEf07557DBE41d03;
    address internal constant CONSENSUS = 0xc855761D619f6002923507cE68B84d7689C2aa96;
    address internal constant USDCE = 0x2a22f9c3b484c3629090FeED35F17Ff8F88f76F0;

    address internal constant SAFE_150 = 0xFf51A5898e281Db6DfC7855790607438dF2ca44b;
    address internal constant SAFE_FACTORY_150 = 0x14F2982D601c9458F93bd70B218933A6f8165e7b;
    address internal constant MULTISEND_CALL_ONLY_150 = 0xA83c336B20401Af773B6219BA5027174338D1836;
    address internal constant FALLBACK_HANDLER_150 = 0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4;
    address internal constant MODULE_PROXY_FACTORY = 0x000000000000aDdB49795b0f9bA5BC298cDda236;

    bytes32 internal constant SAFE_TX_TYPEHASH =
        0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;
    bytes4 internal constant SIGNATURE_VERIFY = bytes4(keccak256("signatureVerify(bytes32,bytes32,bytes32)"));

    event OracleResult(bytes32 indexed requestId, address indexed sponsor, bytes result, bool approved);
    event Claimed(bytes32 indexed requestId, address indexed sentinel, uint96 bondReturn, uint96 feeReward);

    function setUp() public override {
        string memory rpc = vm.envOr("GNOSIS_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true, "set GNOSIS_RPC_URL to run the Gnosis Chain fork tests");
            return;
        }
        uint256 blockNumber = vm.envOr("FORK_BLOCK", uint256(0));
        if (blockNumber == 0) vm.createSelectFork(rpc);
        else vm.createSelectFork(rpc, blockNumber);
        super.setUp();
    }

    function _deployInfra() internal override {
        address[5] memory canonical =
            [SAFE_150, SAFE_FACTORY_150, MULTISEND_CALL_ONLY_150, FALLBACK_HANDLER_150, MODULE_PROXY_FACTORY];
        for (uint256 i; i < canonical.length; i++) {
            require(canonical[i].code.length > 0, "canonical deployment missing on this chain");
        }
        require(EIP2470_FACTORY.code.length > 0, "EIP-2470 factory missing");
        safeSingleton = Safe(payable(SAFE_150));
        safeFactory = SafeProxyFactory(SAFE_FACTORY_150);
        multiSend = MultiSendCallOnly(MULTISEND_CALL_ONLY_150);
        fallbackHandler = FALLBACK_HANDLER_150;
        moduleFactory = ModuleProxyFactory(MODULE_PROXY_FACTORY);
    }

    /// @dev The production market. The suite's constants must match it, or the expectations are wrong.
    function _deployMarket() internal override {
        IOracleConfig c = IOracleConfig(ORACLE);
        require(c.FEE_TOKEN() == USDCE, "fee token");
        require(c.PROPOSER() == CONSENSUS, "proposer");
        require(c.fee() == REQUEST_FEE, "fee");
        require(c.bondMultiplier() == BOND_MULTIPLIER, "bond multiplier");
        require(c.slashingMultiplier() == SLASHING_MULTIPLIER, "slashing multiplier");
        require(c.COMMIT_WINDOW() == COMMIT_WINDOW && c.REVEAL_WINDOW() == REVEAL_WINDOW, "windows");
        require(c.GOVERNANCE_DELAY() == GOVERNANCE_DELAY, "governance delay");
        require(c.ARBITRATION_TIMEOUT() == ARBITRATION_TIMEOUT, "arbitration timeout");

        usdce = FeeToken(USDCE);
        oracle = ISentinelOracle(ORACLE);
        governance = c.GOVERNANCE();
        arbitrator = c.ARBITRATOR();
        proposer = CONSENSUS;
        fundsReceiver = c.protocolFundsReceiver();
    }

    /// @dev Real USDC.e cannot be minted: overwrite the balance (additively).
    function _fund(address token, address to, uint256 amount) internal override {
        deal(token, to, ERC20(token).balanceOf(to) + amount);
    }

    /*//////////////////////////////////////////////////////////////
                FULL LIFECYCLE THROUGH THE REAL CONSENSUS
    //////////////////////////////////////////////////////////////*/

    struct Proposal {
        SafeTx tx_;
        bytes32 safeTxHash;
        bytes32 requestId;
        uint64 epoch;
    }

    /// @dev A Safenet user (the sponsor) submits a Safe transaction for checking: Consensus posts the
    ///      oracle request and the sponsor pays the 0.40 USDC.e fee.
    function _propose(uint256 nonce) internal returns (Proposal memory p) {
        p.tx_ = SafeTx({
            chainId: 100,
            safe: makeAddr("customerSafe"),
            to: makeAddr("customerRecipient"),
            value: 1 ether,
            data: "",
            operation: 0,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: address(0),
            nonce: nonce
        });
        vm.recordLogs();
        vm.prank(sponsor);
        p.safeTxHash = IConsensus(CONSENSUS).proposeTransaction(ORACLE, "", p.tx_);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 newRequest =
            keccak256("NewRequest(bytes32,address,uint96,uint96,uint24,uint96,uint64,uint64)");
        bytes32 proposed = keccak256(
            "TransactionProposed(bytes32,bytes32,address,uint64,bytes,(uint256,address,address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256))"
        );
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter == ORACLE && logs[i].topics[0] == newRequest) {
                p.requestId = logs[i].topics[1];
            }
            if (logs[i].emitter == CONSENSUS && logs[i].topics[0] == proposed) {
                (p.epoch) = abi.decode(logs[i].data, (uint64));
            }
        }
        require(p.requestId != bytes32(0), "no NewRequest from the production oracle");
    }

    function _structHash(SafeTx memory t) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                t.to,
                t.value,
                keccak256(t.data),
                t.operation,
                t.safeTxGas,
                t.baseGas,
                t.gasPrice,
                t.gasToken,
                t.refundReceiver,
                t.nonce
            )
        );
    }

    /**
     * @dev Validation, SIMULATED. Validators watch for `OracleResult(approved = true)` and then produce
     *      a FROST threshold signature offchain; a fork cannot produce that signature. Only the
     *      coordinator's signature check is mocked; Consensus' own attestation logic runs for real.
     */
    function _simulateAttestation(Proposal memory p) internal {
        vm.mockCall(
            IConsensus(CONSENSUS).getCoordinator(),
            abi.encodeWithSelector(SIGNATURE_VERIFY),
            abi.encode(uint256(1), uint256(2), uint256(3))
        );
        IConsensus(CONSENSUS)
            .attestTransaction(
                p.epoch,
                ORACLE,
                keccak256(""),
                p.tx_.chainId,
                p.tx_.safe,
                _structHash(p.tx_),
                bytes32(uint256(1))
            );
        vm.clearMockedCalls();
    }

    /// propose (real Consensus) -> approve + commit -> reveal (OracleResult approved) -> attest -> claim
    function test_fork_lifecycle_proposeCommitRevealAttestClaim() public {
        uint256 s0 = usdce.balanceOf(address(safe));
        Proposal memory p = _propose(0);

        _commitAsSafe(oracle, USDCE, p.requestId, true, SALT);
        assertEq(usdce.balanceOf(address(safe)), s0 - BOND, "800 USDC.e bond posted by the Safe");
        assertEq(usdce.allowance(address(safe), ORACLE), 0, "the bond used the whole allowance");

        _toRevealWindow();
        vm.expectEmit(true, true, false, true, ORACLE);
        emit OracleResult(p.requestId, sponsor, "", true);
        _revealAsSafe(oracle, p.requestId, true, SALT); // the only committer: settles and finalizes

        _simulateAttestation(p);
        vm.prank(sponsor);
        vm.expectRevert(bytes4(keccak256("AlreadyAttested()")));
        IConsensus(CONSENSUS).proposeTransaction(ORACLE, "", p.tx_);

        vm.expectEmit(true, true, false, true, ORACLE);
        emit Claimed(p.requestId, address(safe), uint96(BOND), REQUEST_FEE);
        _sendOrFail(ORACLE, abi.encodeCall(ISentinelOracle.claim, (p.requestId)));

        assertEq(usdce.balanceOf(address(safe)), s0 + REQUEST_FEE, "bond back + 0.40 fee, to the Safe");
        assertEq(usdce.balanceOf(server.addr), 0, "the key never holds USDC.e");
    }

    /// A deny vote: the request resolves denied, nothing to attest, the Safe still earns the fee.
    function test_fork_lifecycle_denyVote() public {
        uint256 s0 = usdce.balanceOf(address(safe));
        Proposal memory p = _propose(1);
        _commitAsSafe(oracle, USDCE, p.requestId, false, SALT);
        _toRevealWindow();
        vm.expectEmit(true, true, false, true, ORACLE);
        emit OracleResult(p.requestId, sponsor, "", false);
        _revealAsSafe(oracle, p.requestId, false, SALT);
        _sendOrFail(ORACLE, abi.encodeCall(ISentinelOracle.claim, (p.requestId)));
        assertEq(usdce.balanceOf(address(safe)), s0 + REQUEST_FEE);
    }

    /// Dispute against a second sentinel: frozen, the arbitrator does not rule within 28 days,
    /// the role key times it out and recovers the full bond.
    function test_fork_lifecycle_disputeThenTimeoutArbitration() public {
        uint256 s0 = usdce.balanceOf(address(safe));
        Proposal memory p = _propose(2);
        _commitAsSafe(oracle, USDCE, p.requestId, true, SALT);
        _commitAs(peer.addr, p.requestId, false, SALT);
        _toRevealWindow();
        _revealAsSafe(oracle, p.requestId, true, SALT);
        _revealAs(peer.addr, p.requestId, false, SALT);

        vm.roll(block.number + ARBITRATION_TIMEOUT + 1);
        _sendOrFail(ORACLE, abi.encodeCall(ISentinelOracle.timeoutArbitration, (p.requestId)));
        _sendOrFail(ORACLE, abi.encodeCall(ISentinelOracle.claim, (p.requestId)));
        assertEq(usdce.balanceOf(address(safe)), s0, "bond returned in full");
    }

    /// The Safe is a live, active sentinel on the production oracle after governance registration.
    function test_fork_safeIsRegisteredOnProduction() public view {
        (bool ok, bytes memory ret) =
            ORACLE.staticcall(abi.encodeWithSignature("sentinelActiveAt(address)", address(safe)));
        assertTrue(ok);
        uint256 activeAt = abi.decode(ret, (uint256));
        assertGt(activeAt, 0);
        assertLe(activeAt, block.number);
    }
}
