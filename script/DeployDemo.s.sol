// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { SafeProxyFactory } from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { MultiSendCallOnly } from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { Safe7579 } from "safe7579/Safe7579.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { SmartSession } from "smartsessions/SmartSession.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { EncodeLib } from "smartsessions/lib/EncodeLib.sol";
import { TimeFramePolicy } from "smartsessions/external/policies/TimeFramePolicy.sol";
import { SimpleGasPolicy } from "smartsessions/external/policies/SimpleGasPolicy.sol";
import { ISessionValidator } from "smartsessions/interfaces/ISessionValidator.sol";
import { Session, PermissionId } from "smartsessions/DataTypes.sol";
import { OwnableValidator } from "core-modules/OwnableValidator/OwnableValidator.sol";

import { FunctionWhitelistPolicy } from "../src/policies/FunctionWhitelistPolicy.sol";
import { AddressWhitelistPolicy } from "../src/policies/AddressWhitelistPolicy.sol";
import { SpendingLimitPolicy } from "../src/policies/SpendingLimitPolicy.sol";
import { GasFeeCapPolicy } from "../src/policies/GasFeeCapPolicy.sol";
import { MaliciousDelegation } from "../src/examples/MaliciousDelegation.sol";
import { MockERC20 } from "../test/utils/MockERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SessionSetup } from "./lib/SessionSetup.sol";

/**
 * @notice Local demonstration (anvil, Prague). Driven by script/demo.sh:
 *
 *   forge script script/DeployDemo.s.sol --rpc-url $RPC --broadcast            # deploy + configure
 *   forge script script/DeployDemo.s.sol --sig "userOp(string)" <scenario> ... # build a signed op
 *   forge script script/DeployDemo.s.sol --sig "leadershipAddOwner()" --broadcast
 *
 * Keys come from anvil's default mnemonic. NEVER reuse this script with real keys.
 * On anvil, the canonical v0.7 EntryPoint is installed with anvil_setCode if missing.
 */
contract DeployDemo is Script {
    string internal constant MNEMONIC = "test test test test test test test test test test test junk";
    address internal constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    string internal constant OUT = "deployments/demo.json";

    uint256 internal constant THRESHOLD = 3;

    // Roles (anvil mnemonic indices): 0 deployer/relayer, 1-5 leadership, 6 session key.
    function _key(uint32 i) internal pure returns (uint256) {
        return vm.deriveKey(MNEMONIC, i);
    }

    // Fresh, zero-balance destinations so balance deltas are easy to read.
    address internal constant ALICE = address(uint160(uint256(keccak256("demo.alice"))));
    address internal constant BOB = address(uint160(uint256(keccak256("demo.bob"))));
    address internal constant ATTACKER = address(uint160(uint256(keccak256("demo.attacker"))));

    struct Deployment {
        address safe;
        address safe7579;
        address smartSession;
        address ownableValidator;
        address timeFramePolicy;
        address gasPolicy;
        address gasFeeCapPolicy;
        address functionPolicy;
        address addressPolicy;
        address spendingPolicy;
        address usdc;
        address multiSend;
        address malicious;
        bytes32 permissionId;
    }

    /*//////////////////////////////////////////////////////////////
                                 DEPLOY
    //////////////////////////////////////////////////////////////*/

    function run() external {
        _ensureEntryPoint();
        Deployment memory d;

        vm.startBroadcast(_key(0));
        Safe singleton = new Safe();
        SafeProxyFactory factory = new SafeProxyFactory();
        d.multiSend = address(new MultiSendCallOnly());
        d.safe7579 = address(new Safe7579());
        d.smartSession = address(new SmartSession());
        d.ownableValidator = address(new OwnableValidator());
        d.timeFramePolicy = address(new TimeFramePolicy());
        d.gasPolicy = address(new SimpleGasPolicy());
        d.gasFeeCapPolicy = address(new GasFeeCapPolicy());
        d.functionPolicy = address(new FunctionWhitelistPolicy());
        d.addressPolicy = address(new AddressWhitelistPolicy());
        d.spendingPolicy = address(new SpendingLimitPolicy());
        d.malicious = address(new MaliciousDelegation());
        MockERC20 usdc = new MockERC20();
        d.usdc = address(usdc);

        address[] memory owners = new address[](5);
        for (uint32 i; i < 5; i++) {
            owners[i] = vm.addr(_key(i + 1));
        }
        bytes memory setup = abi.encodeCall(
            Safe.setup, (owners, THRESHOLD, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        d.safe = address(factory.createProxyWithNonce(address(singleton), setup, uint256(block.timestamp)));

        (bool ok,) = d.safe.call{ value: 10 ether }("");
        require(ok, "fund");
        usdc.mint(d.safe, 1_000_000e6);

        // Leadership tx #1: attach Safe7579 with SmartSession as its only validator.
        _leadership(
            d.safe,
            d.multiSend,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (SessionSetup.attachSafe7579(d.safe, d.safe7579, d.smartSession))
            ),
            Enum.Operation.DelegateCall
        );

        // Leadership tx #2: create the restricted session.
        Session[] memory sessions = new Session[](1);
        sessions[0] = _session(d);
        _leadership(
            d.safe,
            d.smartSession,
            abi.encodeCall(ISmartSession.enableSessions, (sessions)),
            Enum.Operation.Call
        );
        vm.stopBroadcast();

        d.permissionId = PermissionId.unwrap(SmartSession(d.smartSession).getPermissionId(sessions[0]));
        _write(d);
    }

    /// @dev Safe7579 hard-codes the canonical v0.7 EntryPoint. On a local anvil chain, install the
    ///      audited v0.7 runtime code there (on the node via anvil_setCode, and in this simulation).
    function _ensureEntryPoint() internal {
        if (ENTRYPOINT.code.length != 0) return;
        require(block.chainid == 31_337, "no EntryPoint v0.7 at canonical address");
        bytes memory code = address(new EntryPoint()).code;
        vm.rpc("anvil_setCode", string.concat('["', vm.toString(ENTRYPOINT), '","', vm.toString(code), '"]'));
        vm.etch(ENTRYPOINT, code);
    }

    function _session(Deployment memory d) internal view returns (Session memory) {
        address[] memory recipients = new address[](2);
        recipients[0] = ALICE;
        recipients[1] = BOB;

        FunctionWhitelistPolicy.Permission[] memory perms = new FunctionWhitelistPolicy.Permission[](1);
        perms[0] = FunctionWhitelistPolicy.Permission({ target: d.usdc, selector: IERC20.transfer.selector });

        SpendingLimitPolicy.AssetLimit[] memory limits = new SpendingLimitPolicy.AssetLimit[](2);
        limits[0] = SpendingLimitPolicy.AssetLimit({
            asset: address(0), maxPerTx: 1 ether, maxPerPeriod: 5 ether, period: 1 days
        });
        limits[1] = SpendingLimitPolicy.AssetLimit({
            asset: d.usdc, maxPerTx: 1000e6, maxPerPeriod: 3000e6, period: 1 days
        });

        SessionSetup.SessionParams memory p;
        p.validator = ISessionValidator(d.ownableValidator);
        p.signer = vm.addr(_key(6));
        p.validUntil = uint48(block.timestamp + 30 days);
        p.gasUnitsLimit = 1_000_000_000;
        p.gasCostLimit = 0.1 ether;
        p.maxFeePerGas = 100 gwei;
        p.allowNativeTransfers = true;
        p.permissions = perms;
        p.recipients = recipients;
        p.limits = limits;
        return SessionSetup.exchangeSession(
            p,
            SessionSetup.Policies({
                timeFrame: d.timeFramePolicy,
                gas: d.gasPolicy,
                gasFeeCap: d.gasFeeCapPolicy,
                functionWhitelist: d.functionPolicy,
                addressWhitelist: d.addressPolicy,
                spendingLimit: d.spendingPolicy
            })
        );
    }

    /*//////////////////////////////////////////////////////////////
                         SCENARIOS (built, not sent)
    //////////////////////////////////////////////////////////////*/

    /// @notice Writes `handleOps([op])` calldata to deployments/op.hex and the matching
    ///         `SmartSession.validateUserOp(op, hash)` calldata to deployments/validate.hex.
    function userOp(string calldata scenario) external {
        Deployment memory d = _read();
        bytes memory callData = _scenarioCallData(d, keccak256(bytes(scenario)));

        PackedUserOperation memory op;
        op.sender = d.safe;
        op.nonce = IEntryPoint(ENTRYPOINT).getNonce(d.safe, uint192(bytes24(bytes20(d.smartSession))));
        op.callData = callData;
        op.accountGasLimits = bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000)));
        op.preVerificationGas = 100_000;
        if (keccak256(bytes(scenario)) == keccak256("fee-extraction")) {
            // In-policy transfer, but an absurd fee the Safe would pay to the (attacker's) bundler.
            op.accountGasLimits = bytes32(abi.encodePacked(uint128(600_000), uint128(200_000)));
            op.preVerificationGas = 4_000_000;
            op.gasFees = bytes32(abi.encodePacked(uint128(1000 gwei), uint128(1000 gwei)));
        }

        bytes32 userOpHash = IEntryPoint(ENTRYPOINT).getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key(6), userOpHash);
        op.signature = EncodeLib.encodeUse(PermissionId.wrap(d.permissionId), abi.encodePacked(r, s, v));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.writeFile(
            "deployments/op.hex",
            vm.toString(abi.encodeCall(IEntryPoint.handleOps, (ops, payable(vm.addr(_key(0))))))
        );
        vm.writeFile(
            "deployments/validate.hex",
            vm.toString(abi.encodeCall(SmartSession.validateUserOp, (op, userOpHash)))
        );
    }

    function _scenarioCallData(Deployment memory d, bytes32 s) internal pure returns (bytes memory) {
        if (s == keccak256("valid-eth")) return _call(ALICE, 1 ether, "");
        if (s == keccak256("valid-usdc")) {
            return _call(d.usdc, 0, abi.encodeCall(IERC20.transfer, (BOB, 1000e6)));
        }
        if (s == keccak256("unauthorized-recipient")) return _call(ATTACKER, 1 ether, "");
        if (s == keccak256("over-limit")) return _call(ALICE, 2 ether, "");
        if (s == keccak256("add-owner")) {
            return _call(
                d.safe, 0, abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", ATTACKER, 1)
            );
        }
        if (s == keccak256("install-module")) {
            return abi.encodeWithSignature("installModule(uint256,address,bytes)", 2, ATTACKER, "");
        }
        if (s == keccak256("drain")) return _call(ATTACKER, 10 ether, "");
        if (s == keccak256("fee-extraction")) return _call(ALICE, 1 wei, "");
        revert("unknown scenario");
    }

    function _call(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(to, value, data))
        );
    }

    /*//////////////////////////////////////////////////////////////
                       ROOT AUTHORITY (leadership)
    //////////////////////////////////////////////////////////////*/

    function leadershipAddOwner() external {
        Deployment memory d = _read();
        address newLeader = address(uint160(uint256(keccak256("demo.newLeader"))));
        vm.startBroadcast(_key(0));
        _leadership(
            d.safe,
            d.safe,
            abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", newLeader, THRESHOLD),
            Enum.Operation.Call
        );
        vm.stopBroadcast();
    }

    function leadershipRevokeSession() external {
        Deployment memory d = _read();
        vm.startBroadcast(_key(0));
        _leadership(
            d.safe,
            d.smartSession,
            abi.encodeCall(ISmartSession.removeSession, (PermissionId.wrap(d.permissionId))),
            Enum.Operation.Call
        );
        vm.stopBroadcast();
    }

    /// @dev Signs with leadership keys 1..3 (sorted by address) and relays from the deployer.
    function _leadership(address safe, address to, bytes memory data, Enum.Operation op) internal {
        Safe s = Safe(payable(safe));
        bytes32 h = s.getTransactionHash(to, 0, data, op, 0, 0, 0, address(0), address(0), s.nonce());
        uint256[] memory keys = new uint256[](THRESHOLD);
        for (uint32 i; i < THRESHOLD; i++) {
            keys[i] = _key(i + 1);
        }
        for (uint256 i; i < keys.length; i++) {
            for (uint256 j = i + 1; j < keys.length; j++) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        bytes memory sigs;
        for (uint256 i; i < keys.length; i++) {
            (uint8 v, bytes32 r, bytes32 ss) = vm.sign(keys[i], h);
            sigs = abi.encodePacked(sigs, r, ss, v);
        }
        require(
            s.execTransaction(to, 0, data, op, 0, 0, 0, address(0), payable(address(0)), sigs),
            "leadership tx"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                  I/O
    //////////////////////////////////////////////////////////////*/

    function _write(Deployment memory d) internal {
        string memory k = "demo";
        vm.serializeAddress(k, "safe", d.safe);
        vm.serializeAddress(k, "safe7579", d.safe7579);
        vm.serializeAddress(k, "smartSession", d.smartSession);
        vm.serializeAddress(k, "ownableValidator", d.ownableValidator);
        vm.serializeAddress(k, "timeFramePolicy", d.timeFramePolicy);
        vm.serializeAddress(k, "gasPolicy", d.gasPolicy);
        vm.serializeAddress(k, "gasFeeCapPolicy", d.gasFeeCapPolicy);
        vm.serializeAddress(k, "functionPolicy", d.functionPolicy);
        vm.serializeAddress(k, "addressPolicy", d.addressPolicy);
        vm.serializeAddress(k, "spendingPolicy", d.spendingPolicy);
        vm.serializeAddress(k, "usdc", d.usdc);
        vm.serializeAddress(k, "multiSend", d.multiSend);
        vm.serializeAddress(k, "malicious", d.malicious);
        vm.serializeAddress(k, "entryPoint", ENTRYPOINT);
        vm.serializeAddress(k, "sessionKey", vm.addr(_key(6)));
        vm.serializeAddress(k, "alice", ALICE);
        vm.serializeAddress(k, "bob", BOB);
        vm.serializeAddress(k, "attacker", ATTACKER);
        string memory json = vm.serializeBytes32(k, "permissionId", d.permissionId);
        vm.writeJson(json, OUT);
    }

    function _read() internal view returns (Deployment memory d) {
        string memory json = vm.readFile(OUT);
        d.safe = vm.parseJsonAddress(json, ".safe");
        d.safe7579 = vm.parseJsonAddress(json, ".safe7579");
        d.smartSession = vm.parseJsonAddress(json, ".smartSession");
        d.usdc = vm.parseJsonAddress(json, ".usdc");
        d.permissionId = vm.parseJsonBytes32(json, ".permissionId");
    }
}
