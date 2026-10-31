// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, Vm } from "forge-std/Test.sol";

// Safe v1.4.1 (reused, audited)
import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { SafeProxyFactory } from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { MultiSendCallOnly } from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";

// ERC-4337 v0.7 EntryPoint, etched at the canonical address (reused)
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";

// Safe7579 adapter v1.0.0 (reused, audited)
import { Safe7579 } from "safe7579/Safe7579.sol";
import { ExecutionHelper } from "safe7579/core/ExecutionHelper.sol";

// ERC-7579 helpers
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { ModeLib, ModeCode } from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";

// SmartSessions (reused, audited) + Rhinestone OwnableValidator as the session signer check
import { SmartSession } from "smartsessions/SmartSession.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { EncodeLib } from "smartsessions/lib/EncodeLib.sol";
import { TimeFramePolicy } from "smartsessions/external/policies/TimeFramePolicy.sol";
import { SimpleGasPolicy } from "smartsessions/external/policies/SimpleGasPolicy.sol";
import { ISessionValidator } from "smartsessions/interfaces/ISessionValidator.sol";
import {
    Session,
    PermissionId,
    ActionData,
    PolicyData,
    FALLBACK_ACTIONID,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG
} from "smartsessions/DataTypes.sol";
import { OwnableValidator } from "core-modules/OwnableValidator/OwnableValidator.sol";

// This template
import { FunctionWhitelistPolicy } from "src/policies/FunctionWhitelistPolicy.sol";
import { AddressWhitelistPolicy } from "src/policies/AddressWhitelistPolicy.sol";
import { SpendingLimitPolicy } from "src/policies/SpendingLimitPolicy.sol";
import { GasFeeCapPolicy } from "src/policies/GasFeeCapPolicy.sol";
import { SessionSetup } from "script/lib/SessionSetup.sol";
import { ConfigId } from "src/interfaces/ISessionPolicy.sol";
import { MockERC20 } from "./MockERC20.sol";

/// @dev Safe v1.4.1 admin surface (inherited functions are not reachable via `Safe.x` in encodeCall).
interface ISafeAdmin {
    function addOwnerWithThreshold(address owner, uint256 threshold) external;
    function removeOwner(address prevOwner, address owner, uint256 threshold) external;
    function changeThreshold(uint256 threshold) external;
    function enableModule(address module) external;
    function disableModule(address prevModule, address module) external;
    function setGuard(address guard) external;
    function setFallbackHandler(address handler) external;
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool);
}

/**
 * @notice Deploys the full, real stack - no mocked policy results:
 *
 *   leadership (3-of-5 owners) ──execTransaction──▶ Safe v1.4.1
 *                                                    ├─ module + fallback handler: Safe7579
 *                                                    └─ 7579 validator: SmartSession
 *   session key ─signs userOp─▶ EntryPoint.handleOps ─▶ Safe ─▶ Safe7579 ─▶ SmartSession
 *                                                        └─ OwnableValidator (signature)
 *                                                        └─ TimeFramePolicy (expiry)
 *                                                        └─ FunctionWhitelist / AddressWhitelist / SpendingLimit
 */
abstract contract SessionTestBase is Test {
    address internal constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    uint256 internal constant OWNER_COUNT = 5;
    uint256 internal constant THRESHOLD = 3;
    uint48 internal constant SESSION_DURATION = 30 days;
    uint128 internal constant SESSION_GAS_UNITS = 1_000_000_000;
    uint128 internal constant SESSION_GAS_COST = 0.1 ether;
    uint128 internal constant SESSION_MAX_FEE = 100 gwei;

    uint128 internal constant ETH_PER_TX = 1 ether;
    uint128 internal constant ETH_PER_DAY = 5 ether;
    uint128 internal constant USDC_PER_TX = 1000e6;
    uint128 internal constant USDC_PER_DAY = 3000e6;

    uint256 internal constant SAFE_ETH = 100 ether;
    uint256 internal constant SAFE_USDC = 1_000_000e6;

    // Reused infrastructure
    IEntryPoint internal entryPoint;
    Safe internal safeSingleton;
    SafeProxyFactory internal safeFactory;
    MultiSendCallOnly internal multiSend;
    Safe7579 internal safe7579;
    SmartSession internal smartSession;
    OwnableValidator internal ownableValidator;
    TimeFramePolicy internal timeFramePolicy;
    SimpleGasPolicy internal gasPolicy;
    GasFeeCapPolicy internal gasFeeCapPolicy;

    // Custom controls (this template)
    FunctionWhitelistPolicy internal functionPolicy;
    AddressWhitelistPolicy internal addressPolicy;
    SpendingLimitPolicy internal spendingPolicy;

    MockERC20 internal usdc;
    Safe internal safe;

    // Actors
    uint256[] internal ownerKeys;
    address[] internal owners;
    address internal sessionKey;
    uint256 internal sessionKeyPk;
    address internal alice; // whitelisted withdrawal destination
    address internal bob; // whitelisted withdrawal destination
    address internal attacker; // attacker-controlled recipient
    address payable internal bundler;

    PermissionId internal permissionId;
    /// @dev The ConfigId under which the three action policies of `session` store their state.
    ConfigId internal actionConfigId;

    function setUp() public virtual {
        // Canonical v0.7 runtime code at the canonical address (Safe7579 hard-codes it).
        vm.etch(ENTRYPOINT_V07, address(new EntryPoint()).code);
        entryPoint = IEntryPoint(ENTRYPOINT_V07);
        safeSingleton = new Safe();
        safeFactory = new SafeProxyFactory();
        multiSend = new MultiSendCallOnly();
        safe7579 = new Safe7579();
        smartSession = new SmartSession();
        ownableValidator = new OwnableValidator();
        timeFramePolicy = new TimeFramePolicy();
        gasPolicy = new SimpleGasPolicy();
        gasFeeCapPolicy = new GasFeeCapPolicy();

        functionPolicy = new FunctionWhitelistPolicy();
        addressPolicy = new AddressWhitelistPolicy();
        spendingPolicy = new SpendingLimitPolicy();
        usdc = new MockERC20();

        for (uint256 i; i < OWNER_COUNT; i++) {
            (address o, uint256 k) = makeAddrAndKey(string.concat("leader", vm.toString(i)));
            owners.push(o);
            ownerKeys.push(k);
        }
        (sessionKey, sessionKeyPk) = makeAddrAndKey("sessionKey");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        attacker = makeAddr("attacker");
        bundler = payable(makeAddr("bundler"));

        safe = _deploySafe();
        vm.deal(address(safe), SAFE_ETH);
        usdc.mint(address(safe), SAFE_USDC);

        // Leadership tx #1: attach Safe7579 + SmartSession.
        _execLeadership(
            address(multiSend),
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (SessionSetup.attachSafe7579(address(safe), address(safe7579), address(smartSession)))
            ),
            Enum.Operation.DelegateCall
        );

        // Leadership tx #2: create the restricted exchange session.
        permissionId = _enableSession(_exchangeSession(sessionKey, bytes32(0), _defaultRecipients()));
        actionConfigId = _actionConfigId(permissionId);
    }

    /*//////////////////////////////////////////////////////////////
                              SAFE / ROOT
    //////////////////////////////////////////////////////////////*/

    function _deploySafe() internal returns (Safe) {
        bytes memory setup = abi.encodeCall(
            Safe.setup, (owners, THRESHOLD, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        return Safe(payable(address(safeFactory.createProxyWithNonce(address(safeSingleton), setup, 0))));
    }

    /// @dev Executes a Safe transaction signed by THRESHOLD distinct owners (sorted by address).
    function _execLeadership(address to, bytes memory data, Enum.Operation op) internal {
        _execLeadership(to, 0, data, op);
    }

    function _execLeadership(address to, uint256 value, bytes memory data, Enum.Operation op) internal {
        bytes memory sigs = _leadershipSignatures(safe, to, value, data, op, THRESHOLD);
        require(_execWithSignatures(to, value, data, op, sigs), "leadership tx failed");
    }

    function _execWithSignatures(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        bytes memory sigs
    ) internal returns (bool) {
        return safe.execTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), sigs);
    }

    function _leadershipSignatures(
        Safe s,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        uint256 count
    ) internal view returns (bytes memory sigs) {
        sigs = _signSorted(_safeTxHash(s, to, value, data, op), count);
    }

    function _safeTxHash(Safe s, address to, uint256 value, bytes memory data, Enum.Operation op)
        internal
        view
        returns (bytes32)
    {
        uint256 nonce = s.nonce();
        return s.getTransactionHash(to, value, data, op, 0, 0, 0, address(0), address(0), nonce);
    }

    /// @dev Safe requires signatures ordered by ascending owner address.
    function _signSorted(bytes32 txHash, uint256 count) internal view returns (bytes memory sigs) {
        uint256[] memory keys = _sortedOwnerKeys();
        for (uint256 i; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], txHash);
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

    /*//////////////////////////////////////////////////////////////
                               SESSIONS
    //////////////////////////////////////////////////////////////*/

    function _defaultRecipients() internal view returns (address[] memory r) {
        r = new address[](2);
        r[0] = alice;
        r[1] = bob;
    }

    function _defaultLimits() internal view returns (SpendingLimitPolicy.AssetLimit[] memory l) {
        l = new SpendingLimitPolicy.AssetLimit[](2);
        l[0] = SpendingLimitPolicy.AssetLimit({
            asset: address(0), maxPerTx: ETH_PER_TX, maxPerPeriod: ETH_PER_DAY, period: 1 days
        });
        l[1] = SpendingLimitPolicy.AssetLimit({
            asset: address(usdc), maxPerTx: USDC_PER_TX, maxPerPeriod: USDC_PER_DAY, period: 1 days
        });
    }

    function _defaultPermissions() internal view returns (FunctionWhitelistPolicy.Permission[] memory p) {
        p = new FunctionWhitelistPolicy.Permission[](1);
        p[0] = FunctionWhitelistPolicy.Permission({ target: address(usdc), selector: usdc.transfer.selector });
    }

    function _policies() internal view returns (SessionSetup.Policies memory) {
        return SessionSetup.Policies({
            timeFrame: address(timeFramePolicy),
            gas: address(gasPolicy),
            gasFeeCap: address(gasFeeCapPolicy),
            functionWhitelist: address(functionPolicy),
            addressWhitelist: address(addressPolicy),
            spendingLimit: address(spendingPolicy)
        });
    }

    function _exchangeSession(address signer, bytes32 salt, address[] memory recipients)
        internal
        view
        returns (Session memory)
    {
        SessionSetup.SessionParams memory p;
        p.validator = ISessionValidator(address(ownableValidator));
        p.signer = signer;
        p.salt = salt;
        p.validUntil = uint48(block.timestamp) + SESSION_DURATION;
        p.gasUnitsLimit = SESSION_GAS_UNITS;
        p.gasCostLimit = SESSION_GAS_COST;
        p.maxFeePerGas = SESSION_MAX_FEE;
        p.allowNativeTransfers = true;
        p.permissions = _defaultPermissions();
        p.recipients = recipients;
        p.limits = _defaultLimits();
        return SessionSetup.exchangeSession(p, _policies());
    }

    function _enableSession(Session memory s) internal returns (PermissionId id) {
        Session[] memory list = new Session[](1);
        list[0] = s;
        _execLeadership(
            address(smartSession), abi.encodeCall(ISmartSession.enableSessions, (list)), Enum.Operation.Call
        );
        id = smartSession.getPermissionId(s);
        require(smartSession.isPermissionEnabled(id, address(safe)), "session not enabled");
    }

    /// @dev Catch-all ActionData carrying a single (re)configured policy.
    function _catchAllAction(address policy, bytes memory initData)
        internal
        pure
        returns (ActionData[] memory a)
    {
        PolicyData[] memory p = new PolicyData[](1);
        p[0] = PolicyData({ policy: policy, initData: initData });
        a = new ActionData[](1);
        a[0] = ActionData({
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG,
            actionTarget: FALLBACK_TARGET_FLAG,
            actionPolicies: p
        });
    }

    /// @dev Leadership re-configures one policy of the default session (replaces its config).
    function _reconfigure(address policy, bytes memory initData) internal {
        _execLeadership(
            address(smartSession),
            abi.encodeCall(
                ISmartSession.enableActionPolicies, (permissionId, _catchAllAction(policy, initData))
            ),
            Enum.Operation.Call
        );
    }

    /// @dev Mirrors SmartSessions' IdLib: ConfigId of the catch-all action for `account`.
    function _actionConfigId(PermissionId id) internal view returns (ConfigId) {
        bytes32 actionPolicyId = keccak256(abi.encodePacked(id, FALLBACK_ACTIONID));
        return ConfigId.wrap(keccak256(abi.encodePacked(address(safe), actionPolicyId)));
    }

    /*//////////////////////////////////////////////////////////////
                              USER OPS
    //////////////////////////////////////////////////////////////*/

    function _singleCall(address target, uint256 value, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(target, value, data))
        );
    }

    function _batchCall(Execution[] memory execs) internal pure returns (bytes memory) {
        return abi.encodeCall(
            IERC7579Account.execute, (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(execs))
        );
    }

    function _usdcTransfer(address to, uint256 amount) internal view returns (bytes memory) {
        return _singleCall(address(usdc), 0, abi.encodeCall(usdc.transfer, (to, amount)));
    }

    /// @dev Unsigned userOp for the Safe, using SmartSession as validator (encoded in the nonce key).
    function _userOp(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        uint192 key = uint192(bytes24(bytes20(address(smartSession))));
        op.sender = address(safe);
        op.nonce = entryPoint.getNonce(address(safe), key);
        op.callData = callData;
        op.accountGasLimits = bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000)));
        op.preVerificationGas = 100_000;
        // gasFees = 0 keeps balance assertions exact; real deployments fund the EntryPoint deposit.
    }

    /// @dev Session-key signature in SmartSession USE mode: `0x00 || permissionId || ecdsaSig`.
    function _signAs(PackedUserOperation memory op, uint256 pk, PermissionId id)
        internal
        view
        returns (PackedUserOperation memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, entryPoint.getUserOpHash(op));
        op.signature = EncodeLib.encodeUse(id, abi.encodePacked(r, s, v));
        return op;
    }

    function _sessionOp(bytes memory callData) internal view returns (PackedUserOperation memory) {
        return _signAs(_userOp(callData), sessionKeyPk, permissionId);
    }

    function _submit(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, bundler);
    }

    function _ops(PackedUserOperation memory op) internal pure returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = op;
    }

    /*//////////////////////////////////////////////////////////////
                         BLOCKED-ATTACK EVIDENCE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Asserts an operation is rejected *by SmartSession validation* and nowhere else.
     *
     * Safe7579 replaces any validator revert with `ExecutionFailed()`, so the EntryPoint error alone
     * cannot tell "blocked by policy X" from "broken test setup". We therefore:
     *  1. replay the exact op against SmartSession.validateUserOp as the Safe (what Safe7579 does)
     *     and require the precise `expectedReason` (e.g. PolicyViolation(permissionId, policy));
     *  2. submit it through the real EntryPoint -> Safe -> Safe7579 path and require AA23.
     */
    function _assertRejectedInValidation(PackedUserOperation memory op, bytes memory expectedReason)
        internal
    {
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        vm.prank(address(safe));
        vm.expectRevert(expectedReason);
        smartSession.validateUserOp(op, userOpHash);

        _assertRejectedByEntryPointAA23(op);
    }

    /// @dev Real path: EntryPoint -> Safe -> Safe7579 -> SmartSession reverts during validation.
    function _assertRejectedByEntryPointAA23(PackedUserOperation memory op) internal {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(ExecutionHelper.ExecutionFailed.selector)
            )
        );
        entryPoint.handleOps(_ops(op), bundler);
    }

    function _assertRejectedByEntryPoint(PackedUserOperation memory op, string memory aaReason) internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, aaReason));
        entryPoint.handleOps(_ops(op), bundler);
    }

    function _policyViolation(address policy) internal view returns (bytes memory) {
        return abi.encodeWithSignature("PolicyViolation(bytes32,address)", permissionId, policy);
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIG SNAPSHOT
    //////////////////////////////////////////////////////////////*/

    struct CriticalConfig {
        address[] owners;
        uint256 threshold;
        address[] modules;
        bytes32 guardSlot;
        bytes32 fallbackHandlerSlot;
        bytes32 singletonSlot;
        uint256 ethBalance;
        uint256 usdcBalance;
        bool sessionEnabled;
    }

    // keccak256("guard_manager.guard.address") / keccak256("fallback_manager.handler.address")
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant FALLBACK_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    function _snapshot() internal view returns (CriticalConfig memory c) {
        c.owners = safe.getOwners();
        c.threshold = safe.getThreshold();
        (c.modules,) = safe.getModulesPaginated(address(0x1), 10);
        c.guardSlot = vm.load(address(safe), GUARD_SLOT);
        c.fallbackHandlerSlot = vm.load(address(safe), FALLBACK_SLOT);
        c.singletonSlot = vm.load(address(safe), bytes32(0));
        c.ethBalance = address(safe).balance;
        c.usdcBalance = usdc.balanceOf(address(safe));
        c.sessionEnabled = smartSession.isPermissionEnabled(permissionId, address(safe));
    }

    function _assertUnchanged(CriticalConfig memory a) internal view {
        CriticalConfig memory b = _snapshot();
        assertEq(abi.encode(a.owners), abi.encode(b.owners), "owners changed");
        assertEq(a.threshold, b.threshold, "threshold changed");
        assertEq(abi.encode(a.modules), abi.encode(b.modules), "modules changed");
        assertEq(a.guardSlot, b.guardSlot, "guard changed");
        assertEq(a.fallbackHandlerSlot, b.fallbackHandlerSlot, "fallback handler changed");
        assertEq(a.singletonSlot, b.singletonSlot, "singleton (upgrade) changed");
        assertEq(a.ethBalance, b.ethBalance, "ETH moved");
        assertEq(a.usdcBalance, b.usdcBalance, "USDC moved");
        assertEq(a.sessionEnabled, b.sessionEnabled, "session state changed");
    }
}
