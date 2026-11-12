// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

// Safe v1.5.0
import { Safe } from "@safe-global/safe-smart-account/contracts/Safe.sol";
import { SafeProxyFactory } from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { MultiSendCallOnly } from "@safe-global/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";
import {
    CompatibilityFallbackHandler
} from "@safe-global/safe-smart-account/contracts/handler/CompatibilityFallbackHandler.sol";
import { Enum } from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";

// Architecture A
import { Roles } from "zodiac-roles/Roles.sol";
import { MultiSendUnwrapper } from "zodiac-roles/adapters/MultiSendUnwrapper.sol";
import { Enum as ZodiacEnum } from "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import { ModuleProxyFactory } from "@gnosis.pm/zodiac/contracts/factory/ModuleProxyFactory.sol";

// Architecture B
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { Safe7579 } from "safe7579/Safe7579.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { IValidator } from "erc7579/interfaces/IERC7579Module.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { SmartSession } from "smartsessions/SmartSession.sol";
import { ISmartSession } from "smartsessions/ISmartSession.sol";
import { EncodeLib } from "smartsessions/lib/EncodeLib.sol";
import { TimeFramePolicy } from "smartsessions/external/policies/TimeFramePolicy.sol";
import { SimpleGasPolicy } from "smartsessions/external/policies/SimpleGasPolicy.sol";
import { Session, PermissionId } from "smartsessions/DataTypes.sol";
import { OwnableValidator } from "core-modules/OwnableValidator/OwnableValidator.sol";
import { FunctionWhitelistPolicy } from "../src/policies/FunctionWhitelistPolicy.sol";
import { AddressWhitelistPolicy } from "../src/policies/AddressWhitelistPolicy.sol";
import { SpendingLimitPolicy } from "../src/policies/SpendingLimitPolicy.sol";
import { GasFeeCapPolicy } from "../src/policies/GasFeeCapPolicy.sol";
import { Safe7579BatchPolicy, IBatchedExecUtil } from "../src/policies/engine/Safe7579BatchPolicy.sol";

// Common
import { OwnerOnlyPolicy } from "../src/policies/engine/OwnerOnlyPolicy.sol";
import { TestToken } from "../test/operator-keys/utils/OperatorKeyFixtures.sol";
import { OperatorKeySetup, PolicyConfig } from "./lib/OperatorKeySetup.sol";
import { SessionSetup } from "./lib/SessionSetup.sol";

/**
 * @notice Deploys, configures and exercises both restricted operator-key architectures on one chain,
 *         one phase per invocation so that every phase has its own broadcast receipts
 *         (broadcast/DeployOperatorKeys.s.sol/<chainId>/<phase>-latest.json). Driven by
 *         script/bench-operator-keys.sh against a local anvil (Prague). State between phases is kept
 *         in deployments/operator-keys.json.
 *
 *   shared()                     Safe v1.5.0 singletons, Safe Policy Engine guard + policies, tokens
 *   zodiacSingletons()           Roles v2.1.1 mastercopy (+ libraries), ModuleProxyFactory, MultiSendUnwrapper
 *   sessionsSingletons()         Safe7579 (+ DCUtil), SmartSession, OwnableValidator, session policies,
 *                                Safe7579BatchPolicy   (the ERC-4337 EntryPoint v0.7 is canonical and pre-existing)
 *   zodiacSafe() / sessionsSafe()            per-Safe deployment
 *   fund()                                   test assets (not measured)
 *   zodiacConfigure() / sessionsConfigure()  owner txs: attach, register operator, configure engine, install guards
 *   zodiacExec() / sessionsExec()            one authorized transfer, signed by the operator key, relayed
 *   zodiacBatch() / sessionsBatch()          a 2-transfer batch
 *   zodiacRotate() / sessionsRotate()        owners rotate operator -> operator2 in ONE tx
 *   zodiacRevoke() / sessionsRevoke()        owners revoke operator2
 *
 * Keys: anvil's default mnemonic (0 relayer/bundler/deployer, 1-5 owners, 6 operator, 7 operator2).
 * NEVER use this script with real owner keys: it signs owner transactions locally for the benchmark.
 *
 * Operator signing is KMS/HSM-compatible: the operator key only ever signs a 32-byte digest. With
 * OPERATOR_SIGNER=wallet the script calls `vm.sign(operatorAddress, digest)`, i.e. it uses whatever
 * signer forge was given for that address (`--private-keys`, `--ledger`, `--aws`, `--gcp`, ...).
 */
contract DeployOperatorKeys is Script {
    string internal constant MNEMONIC = "test test test test test test test test test test test junk";
    string internal constant STATE = "deployments/operator-keys.json";
    address internal constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address internal constant EIP2470_FACTORY = 0xce0042B868300000d44A59004Da54A005ffdcf9f;
    uint256 internal constant THRESHOLD = 3;
    uint256 internal constant MAX_PER_TX = 1000e6;
    uint256 internal constant MAX_PER_DAY = 3000e6;
    bytes32 internal constant ROLE = keccak256("OPERATOR");
    bytes32 internal constant ALLOWANCE = keccak256("OPERATOR_DAILY");
    address internal constant ALICE = address(uint160(uint256(keccak256("operator-keys.alice"))));
    address internal constant BOB = address(uint160(uint256(keccak256("operator-keys.bob"))));

    function _key(uint32 i) internal pure returns (uint256) {
        return vm.deriveKey(MNEMONIC, i);
    }

    function _addr(uint32 i) internal pure returns (address) {
        return vm.addr(_key(i));
    }

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    function _get(string memory k) internal view returns (address) {
        return vm.parseJsonAddress(vm.readFile(STATE), string.concat(".", k));
    }

    function _has(string memory k) internal view returns (bool) {
        try vm.readFile(STATE) returns (string memory json) {
            return vm.keyExistsJson(json, string.concat(".", k));
        } catch {
            return false;
        }
    }

    function _set(string memory k, address v) internal {
        string memory json = "{}";
        try vm.readFile(STATE) returns (string memory existing) {
            json = existing;
        } catch { }
        string[] memory keys = vm.parseJsonKeys(json, "$");
        string memory obj = "state";
        for (uint256 i; i < keys.length; i++) {
            if (keccak256(bytes(keys[i])) == keccak256(bytes(k))) continue;
            vm.serializeAddress(obj, keys[i], vm.parseJsonAddress(json, string.concat(".", keys[i])));
        }
        vm.writeJson(vm.serializeAddress(obj, k, v), STATE);
    }

    /*//////////////////////////////////////////////////////////////
                              DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    function _pe(string memory name) internal pure returns (string memory) {
        return string.concat("out/", name, ".sol/", name, ".json");
    }

    function shared() external {
        vm.writeFile(STATE, "{}");
        vm.startBroadcast(_key(0));
        address[13] memory a = [
            address(new Safe()),
            address(new SafeProxyFactory()),
            address(new MultiSendCallOnly()),
            address(new CompatibilityFallbackHandler()),
            vm.deployCode(_pe("SafePolicyGuard"), abi.encode(uint256(1 days), uint256(7 days))),
            vm.deployCode(_pe("ERC20TransferPolicy")),
            vm.deployCode(_pe("MultiSendPolicy")),
            vm.deployCode(_pe("IncreasedThresholdPolicy")),
            vm.deployCode(_pe("AllowedModulePolicy")),
            vm.deployCode(_pe("NativeTransferPolicy")),
            address(new OwnerOnlyPolicy()),
            address(new TestToken("USD Coin", "USDC")),
            address(new TestToken("Bonded collateral", "BOND"))
        ];
        vm.stopBroadcast();
        string[13] memory n = [
            "safeSingleton",
            "safeFactory",
            "multiSend",
            "fallbackHandler",
            "guard",
            "erc20TransferPolicy",
            "multiSendPolicy",
            "increasedThresholdPolicy",
            "allowedModulePolicy",
            "nativeTransferPolicy",
            "ownerOnlyPolicy",
            "usdc",
            "bond"
        ];
        for (uint256 i; i < n.length; i++) {
            _set(n[i], a[i]);
        }
    }

    function zodiacSingletons() external {
        // Roles' WriteOnce stores scopes through the EIP-2470 factory. It exists on public chains; on
        // a local chain install its runtime (from the EIP's presigned deployment tx).
        if (EIP2470_FACTORY.code.length == 0) {
            require(block.chainid == 31_337, "EIP-2470 SingletonFactory missing");
            bytes memory rt =
                hex"6080604052348015600f57600080fd5b506004361060285760003560e01c80634af63f0214602d575b600080fd5b60cf60048036036040811015604157600080fd5b810190602081018135640100000000811115605b57600080fd5b820183602082011115606c57600080fd5b80359060200191846001830284011164010000000083111715608d57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929550509135925060eb915050565b604080516001600160a01b039092168252519081900360200190f35b6000818351602085016000f5939250505056fea26469706673582212206b44f8a82cb6b156bfcc3dc6aadd6df4eefd204bc928a4397fd15dacf6d5320564736f6c63430006020033";
            vm.rpc(
                "anvil_setCode",
                string.concat('["', vm.toString(EIP2470_FACTORY), '","', vm.toString(rt), '"]')
            );
            vm.etch(EIP2470_FACTORY, rt);
        }
        vm.startBroadcast(_key(0));
        address mastercopy = address(new Roles(address(0xdead), address(0xdead), address(0xdead)));
        address factory = address(new ModuleProxyFactory());
        address unwrapper = address(new MultiSendUnwrapper());
        vm.stopBroadcast();
        _set("rolesMastercopy", mastercopy);
        _set("moduleProxyFactory", factory);
        _set("multiSendUnwrapper", unwrapper);
    }

    function sessionsSingletons() external {
        if (ENTRYPOINT.code.length == 0) {
            require(block.chainid == 31_337, "no EntryPoint v0.7 at canonical address");
            bytes memory code = address(new EntryPoint()).code;
            vm.rpc(
                "anvil_setCode", string.concat('["', vm.toString(ENTRYPOINT), '","', vm.toString(code), '"]')
            );
            vm.etch(ENTRYPOINT, code);
        }
        vm.startBroadcast(_key(0));
        Safe7579 adapter = new Safe7579();
        address[9] memory a = [
            address(adapter),
            address(new SmartSession()),
            address(new OwnableValidator()),
            address(new TimeFramePolicy()),
            address(new SimpleGasPolicy()),
            address(new GasFeeCapPolicy()),
            address(new FunctionWhitelistPolicy()),
            address(new AddressWhitelistPolicy()),
            address(new SpendingLimitPolicy())
        ];
        address batchPolicy = address(new Safe7579BatchPolicy());
        vm.stopBroadcast();
        string[9] memory n = [
            "safe7579",
            "smartSession",
            "ownableValidator",
            "timeFramePolicy",
            "simpleGasPolicy",
            "gasFeeCapPolicy",
            "functionWhitelistPolicy",
            "addressWhitelistPolicy",
            "spendingLimitPolicy"
        ];
        for (uint256 i; i < n.length; i++) {
            _set(n[i], a[i]);
        }
        _set("safe7579BatchPolicy", batchPolicy);
        _set("dcUtil", vm.computeCreateAddress(address(adapter), 1));
    }

    function _owners() internal pure returns (address[] memory o) {
        o = new address[](5);
        for (uint32 i; i < 5; i++) {
            o[i] = _addr(i + 1);
        }
    }

    function _deploySafe(uint256 saltNonce, address fh) internal returns (Safe safe) {
        bytes memory setup = abi.encodeCall(
            Safe.setup, (_owners(), THRESHOLD, address(0), "", fh, address(0), 0, payable(address(0)))
        );
        safe = Safe(
            payable(address(
                    SafeProxyFactory(_get("safeFactory"))
                        .createProxyWithNonce(_get("safeSingleton"), setup, saltNonce)
                ))
        );
    }

    function zodiacSafe() external {
        vm.startBroadcast(_key(0));
        Safe safe = _deploySafe(1, _get("fallbackHandler"));
        address roles = ModuleProxyFactory(_get("moduleProxyFactory"))
            .deployModule(
                _get("rolesMastercopy"),
                abi.encodeCall(Roles.setUp, (abi.encode(address(safe), address(safe), address(safe)))),
                1
            );
        vm.stopBroadcast();
        _set("zodiacSafe", address(safe));
        _set("roles", roles);
    }

    function sessionsSafe() external {
        vm.startBroadcast(_key(0));
        Safe safe = _deploySafe(2, _get("fallbackHandler"));
        vm.stopBroadcast();
        _set("sessionsSafe", address(safe));
    }

    /// @dev Test assets for both Safes (its own phase, so it is not counted in any metric).
    function fund() external {
        address[2] memory safes = [_get("zodiacSafe"), _get("sessionsSafe")];
        vm.startBroadcast(_key(0));
        for (uint256 i; i < 2; i++) {
            TestToken(_get("usdc")).mint(safes[i], 1_000_000e6);
            TestToken(_get("bond")).mint(safes[i], 500_000e6);
            (bool ok,) = safes[i].call{ value: 1 ether }("");
            require(ok);
        }
        vm.stopBroadcast();
    }

    /*//////////////////////////////////////////////////////////////
                            OWNER TRANSACTIONS
    //////////////////////////////////////////////////////////////*/

    function _ownerTx(Safe safe, address to, bytes memory data, uint8 op) internal {
        bytes32 h = safe.getTransactionHash(
            to, 0, data, Enum.Operation(op), 0, 0, 0, address(0), address(0), safe.nonce()
        );
        uint256[] memory keys = new uint256[](5);
        for (uint32 i; i < 5; i++) {
            keys[i] = _key(i + 1);
        }
        for (uint256 i; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        bytes memory sigs;
        for (uint256 i; i < THRESHOLD; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            sigs = abi.encodePacked(sigs, r, s, v);
        }
        vm.broadcast(_key(0));
        require(
            safe.execTransaction(
                to, 0, data, Enum.Operation(op), 0, 0, 0, address(0), payable(address(0)), sigs
            ),
            "owner tx failed"
        );
    }

    function _multiSend(Safe safe, bytes memory txs) internal {
        _ownerTx(safe, _get("multiSend"), abi.encodeCall(MultiSendCallOnly.multiSend, (txs)), 1);
    }

    function _common(address safe) internal view returns (PolicyConfig[] memory) {
        address[] memory r = new address[](2);
        r[0] = ALICE;
        r[1] = BOB;
        return OperatorKeySetup.commonPolicies(
            OperatorKeySetup.Common({
                safe: safe,
                token: _get("usdc"),
                recipients: r,
                multiSend: _get("multiSend"),
                erc20TransferPolicy: _get("erc20TransferPolicy"),
                multiSendPolicy: _get("multiSendPolicy"),
                increasedThresholdPolicy: _get("increasedThresholdPolicy"),
                ownerOnlyPolicy: _get("ownerOnlyPolicy")
            })
        );
    }

    function _hardenWithPolicyEngine(Safe safe, PolicyConfig[] memory archEntries) internal {
        _ownerTx(
            safe,
            _get("guard"),
            OperatorKeySetup.configureImmediately(
                OperatorKeySetup.concat(_common(address(safe)), archEntries)
            ),
            0
        );
        _multiSend(safe, OperatorKeySetup.installGuards(address(safe), _get("guard")));
    }

    function _rolesParams() internal view returns (OperatorKeySetup.RolesParams memory) {
        address[] memory r = new address[](2);
        r[0] = ALICE;
        r[1] = BOB;
        return OperatorKeySetup.RolesParams({
            safe: _get("zodiacSafe"),
            roles: _get("roles"),
            multiSend: _get("multiSend"),
            unwrapper: _get("multiSendUnwrapper"),
            token: _get("usdc"),
            recipients: r,
            maxPerTx: MAX_PER_TX,
            maxPerDay: MAX_PER_DAY,
            role: ROLE,
            allowanceKey: ALLOWANCE
        });
    }

    function zodiacConfigure() external {
        Safe safe = Safe(payable(_get("zodiacSafe")));
        _multiSend(safe, OperatorKeySetup.rolesAttach(_rolesParams())); // tx 1: attach Roles + scope
        _ownerTx(safe, _get("roles"), OperatorKeySetup.rolesAssign(_addr(6), ROLE, true), 0); // tx 2
        _hardenWithPolicyEngine(safe, OperatorKeySetup.rolesPolicies(_get("roles"), _get("ownerOnlyPolicy"))); // 3, 4
    }

    function _session(address key) internal view returns (Session memory) {
        address[] memory r = new address[](2);
        r[0] = ALICE;
        r[1] = BOB;
        return OperatorKeySetup.operatorSession(
            OperatorKeySetup.OperatorSession({
                validator: _get("ownableValidator"),
                signer: key,
                token: _get("usdc"),
                recipients: r,
                maxPerTx: MAX_PER_TX,
                maxPerDay: MAX_PER_DAY,
                validUntil: uint48(block.timestamp + 30 days),
                gasUnitsLimit: 1_000_000_000,
                gasCostLimit: 0.1 ether,
                maxFeePerGas: 100 gwei,
                policies: SessionSetup.Policies({
                    timeFrame: _get("timeFramePolicy"),
                    gas: _get("simpleGasPolicy"),
                    gasFeeCap: _get("gasFeeCapPolicy"),
                    functionWhitelist: _get("functionWhitelistPolicy"),
                    addressWhitelist: _get("addressWhitelistPolicy"),
                    spendingLimit: _get("spendingLimitPolicy")
                })
            })
        );
    }

    function _enableSessionsData(address key) internal view returns (bytes memory) {
        Session[] memory list = new Session[](1);
        list[0] = _session(key);
        return abi.encodeCall(ISmartSession.enableSessions, (list));
    }

    function _removeSessionData(address key) internal view returns (bytes memory) {
        return abi.encodeCall(
            ISmartSession.removeSession, (SmartSession(_get("smartSession")).getPermissionId(_session(key)))
        );
    }

    function sessionsConfigure() external {
        Safe safe = Safe(payable(_get("sessionsSafe")));
        _multiSend(safe, SessionSetup.attachSafe7579(address(safe), _get("safe7579"), _get("smartSession"))); // tx 1
        _ownerTx(safe, _get("smartSession"), _enableSessionsData(_addr(6)), 0); // tx 2
        _hardenWithPolicyEngine( // tx 3, 4
            safe,
            OperatorKeySetup.sessionsPolicies(
                OperatorKeySetup.SessionsEntries({
                    smartSession: _get("smartSession"),
                    safe7579: _get("safe7579"),
                    dcUtil: _get("dcUtil"),
                    entryPoint: ENTRYPOINT,
                    ownerOnlyPolicy: _get("ownerOnlyPolicy"),
                    allowedModulePolicy: _get("allowedModulePolicy"),
                    nativeTransferPolicy: _get("nativeTransferPolicy"),
                    batchPolicy: _get("safe7579BatchPolicy"),
                    enableSessions: ISmartSession.enableSessions.selector,
                    removeSession: ISmartSession.removeSession.selector,
                    validateUserOp: IValidator.validateUserOp.selector,
                    batchedExecute: IBatchedExecUtil.execute.selector
                })
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                        OPERATOR (KMS-COMPATIBLE)
    //////////////////////////////////////////////////////////////*/

    /// @dev The only use of the operator key: sign a 32-byte digest.
    function _operatorSign(uint32 index, bytes32 digest) internal returns (bytes memory) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        if (keccak256(bytes(vm.envOr("OPERATOR_SIGNER", string("local")))) == keccak256("wallet")) {
            (v, r, s) = vm.sign(_addr(index), digest); // forge's wallet for that address (KMS, HSM, ...)
        } else {
            (v, r, s) = vm.sign(_key(index), digest);
        }
        return abi.encodePacked(r, s, v);
    }

    function _transfer(address to, uint256 amount) internal view returns (bytes memory) {
        return abi.encodeWithSelector(OperatorKeySetup.TRANSFER, to, amount);
    }

    function _rolesRelay(uint32 operatorIndex, address to, bytes memory data, uint8 op, bytes32 salt)
        internal
    {
        Roles roles = Roles(_get("roles"));
        bytes memory payload = abi.encodeCall(
            Roles.execTransactionWithRole, (to, 0, data, ZodiacEnum.Operation(op), ROLE, true)
        );
        bytes memory signed =
            abi.encodePacked(payload, salt, _operatorSign(operatorIndex, roles.moduleTxHash(payload, salt)));
        vm.broadcast(_key(0)); // relayer
        (bool ok, bytes memory ret) = address(roles).call(signed);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function zodiacExec() external {
        _rolesRelay(6, _get("usdc"), _transfer(ALICE, 100e6), 0, keccak256("exec"));
    }

    function zodiacBatch() external {
        bytes memory txs = abi.encodePacked(
            OperatorKeySetup.multiSendTx(0, _get("usdc"), 0, _transfer(ALICE, 100e6)),
            OperatorKeySetup.multiSendTx(0, _get("usdc"), 0, _transfer(BOB, 200e6))
        );
        _rolesRelay(
            6, _get("multiSend"), abi.encodeCall(MultiSendCallOnly.multiSend, (txs)), 1, keccak256("batch")
        );
    }

    function zodiacRotate() external {
        Safe safe = Safe(payable(_get("zodiacSafe")));
        _multiSend(
            safe,
            abi.encodePacked(
                OperatorKeySetup.multiSendTx(
                    0, _get("roles"), 0, OperatorKeySetup.rolesAssign(_addr(7), ROLE, true)
                ),
                OperatorKeySetup.multiSendTx(
                    0, _get("roles"), 0, OperatorKeySetup.rolesAssign(_addr(6), ROLE, false)
                )
            )
        );
        _rolesRelay(7, _get("usdc"), _transfer(BOB, 1e6), 0, keccak256("after-rotation")); // new key works
    }

    function zodiacRevoke() external {
        _ownerTx(
            Safe(payable(_get("zodiacSafe"))),
            _get("roles"),
            OperatorKeySetup.rolesAssign(_addr(7), ROLE, false),
            0
        );
    }

    function _bundle(uint32 operatorIndex, bytes memory callData) internal {
        address safe = _get("sessionsSafe");
        address smartSession = _get("smartSession");
        PackedUserOperation memory op;
        op.sender = safe;
        op.nonce = IEntryPoint(ENTRYPOINT).getNonce(safe, uint192(bytes24(bytes20(smartSession))));
        op.callData = callData;
        op.accountGasLimits = bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000)));
        op.preVerificationGas = 100_000;
        // zero fees: same accounting as the forge gas benchmark (no prefund; see the docs)
        PermissionId id = SmartSession(smartSession).getPermissionId(_session(_addr(operatorIndex)));
        op.signature =
            EncodeLib.encodeUse(id, _operatorSign(operatorIndex, IEntryPoint(ENTRYPOINT).getUserOpHash(op)));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        // A bundler must give the bundle enough gas for the ops' declared limits (the EntryPoint checks
        // gasleft against callGasLimit), not forge's estimate of what it actually uses.
        vm.broadcast(_key(0)); // bundler
        IEntryPoint(ENTRYPOINT).handleOps{ gas: 4_500_000 }(ops, payable(_addr(0)));
    }

    function _single(address to, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeCall(
            IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(to, 0, data))
        );
    }

    function sessionsExec() external {
        uint256 before = TestToken(_get("usdc")).balanceOf(ALICE);
        _bundle(6, _single(_get("usdc"), _transfer(ALICE, 100e6)));
        // handleOps does not revert on a failed execution: check the effect.
        require(
            TestToken(_get("usdc")).balanceOf(ALICE) == before + 100e6, "sessions transfer did not execute"
        );
    }

    function sessionsBatch() external {
        uint256 before = TestToken(_get("usdc")).balanceOf(BOB);
        Execution[] memory x = new Execution[](2);
        x[0] = Execution(_get("usdc"), 0, _transfer(ALICE, 100e6));
        x[1] = Execution(_get("usdc"), 0, _transfer(BOB, 200e6));
        _bundle(
            6,
            abi.encodeCall(
                IERC7579Account.execute, (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(x))
            )
        );
        require(TestToken(_get("usdc")).balanceOf(BOB) == before + 200e6, "sessions batch did not execute");
    }

    function sessionsRotate() external {
        Safe safe = Safe(payable(_get("sessionsSafe")));
        _multiSend(
            safe,
            abi.encodePacked(
                OperatorKeySetup.multiSendTx(0, _get("smartSession"), 0, _enableSessionsData(_addr(7))),
                OperatorKeySetup.multiSendTx(0, _get("smartSession"), 0, _removeSessionData(_addr(6)))
            )
        );
        uint256 before = TestToken(_get("usdc")).balanceOf(BOB);
        _bundle(7, _single(_get("usdc"), _transfer(BOB, 1e6))); // new key works
        require(TestToken(_get("usdc")).balanceOf(BOB) == before + 1e6, "new session key did not work");
    }

    function sessionsRevoke() external {
        _ownerTx(Safe(payable(_get("sessionsSafe"))), _get("smartSession"), _removeSessionData(_addr(7)), 0);
    }
}
