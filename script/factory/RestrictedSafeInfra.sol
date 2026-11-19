// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm, VmSafe } from "forge-std/Vm.sol";

// Safe v1.5.0 and Zodiac's ModuleProxyFactory: deployed here only on a local chain, where the
// canonical deployments do not exist.
import { Safe } from "@safe-global/safe-smart-account/contracts/Safe.sol";
import { SafeProxyFactory } from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {
    CompatibilityFallbackHandler
} from "@safe-global/safe-smart-account/contracts/handler/CompatibilityFallbackHandler.sol";
import { ModuleProxyFactory } from "@gnosis.pm/zodiac/contracts/factory/ModuleProxyFactory.sol";

import { RestrictedSafePlan } from "./RestrictedSafePlan.sol";

/**
 * @notice The contracts a restricted Safe is built from, and their deployment.
 *
 *   Canonical, never deployed here (overridable in the config's `infrastructure`):
 *     Safe v1.5.0 singleton: Safe on Ethereum mainnet, SafeL2 elsewhere, as Safe{Wallet} does, so that
 *       the Safe Transaction Service indexes it from events
 *     SafeProxyFactory, CompatibilityFallbackHandler                          (safe-global deployments)
 *     Zodiac ModuleProxyFactory                                               (gnosisguild deployments)
 *     EIP-2470 SingletonFactory                                               (Roles stores scopes with it)
 *
 *   Deterministic, deployed by the first person who needs them on a chain, through the CREATE2
 *   deployer at 0x4e59b448...56C with one fixed salt. The address follows from the bytecode only, so it
 *   is the same on every chain and for every deployer:
 *     RestrictedSafeSetup                       this repository
 *     ERC20ApproveCapPolicy, OwnerOnlyPolicy    this repository (src/sentinel)
 *     SafePolicyGuard(delay, expiry)            safe-research/policy-engine, one per (delay, expiry)
 *     AllowPolicy, ERC20TransferPolicy, IncreasedThresholdPolicy
 *     Zodiac Roles v2.1.1 mastercopy, with its Integrity and Packer libraries
 *
 * Bytecode comes from this repository's build artifacts (`out/`), so the addresses depend on the
 * compiler settings in foundry.toml. `bytecode_hash = "none"` keeps them independent of comments and
 * paths. The Roles mastercopy is this repository's build (Zodiac core carries a patch, see patches/),
 * not the Gnosis Guild deployment.
 *
 * On a local chain (chain id 31337) the canonical contracts are deployed the same deterministic way.
 */
library RestrictedSafeInfra {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 internal constant SALT = keccak256("intentguard.restricted-safe.v1");

    // Canonical deployments (the same address on every supported chain)
    address internal constant SAFE_150 = 0xFf51A5898e281Db6DfC7855790607438dF2ca44b;
    address internal constant SAFE_L2_150 = 0xEdd160fEBBD92E350D4D398fb636302fccd67C7e;
    uint256 internal constant ETHEREUM_MAINNET = 1;
    address internal constant SAFE_FACTORY_150 = 0x14F2982D601c9458F93bd70B218933A6f8165e7b;
    address internal constant FALLBACK_HANDLER_150 = 0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4;
    address internal constant MODULE_PROXY_FACTORY = 0x000000000000aDdB49795b0f9bA5BC298cDda236;
    address internal constant EIP2470_FACTORY = 0xce0042B868300000d44A59004Da54A005ffdcf9f;

    uint256 internal constant LOCAL_CHAIN_ID = 31_337;

    // EIP-2470 runtime (from the EIP's presigned deployment) and the CREATE2 deployer runtime, for local chains
    bytes internal constant EIP2470_RUNTIME =
        hex"6080604052348015600f57600080fd5b506004361060285760003560e01c80634af63f0214602d575b600080fd5b60cf60048036036040811015604157600080fd5b810190602081018135640100000000811115605b57600080fd5b820183602082011115606c57600080fd5b80359060200191846001830284011164010000000083111715608d57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929550509135925060eb915050565b604080516001600160a01b039092168252519081900360200190f35b6000818351602085016000f5939250505056fea26469706673582212206b44f8a82cb6b156bfcc3dc6aadd6df4eefd204bc928a4397fd15dacf6d5320564736f6c63430006020033";
    bytes internal constant CREATE2_DEPLOYER_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    string internal constant INTEGRITY =
        "node_modules/zodiac-modifier-roles/contracts/Integrity.sol:Integrity";
    string internal constant PACKER =
        "node_modules/zodiac-modifier-roles/contracts/packers/Packer.sol:Packer";

    /// @dev Canonical contracts the config may replace (zero = use the default).
    struct Overrides {
        address safeSingleton;
        address safeProxyFactory;
        address fallbackHandler;
        address moduleProxyFactory;
    }

    /*//////////////////////////////////////////////////////////////
                               ADDRESSES
    //////////////////////////////////////////////////////////////*/

    /// @notice Every address the Safe is built from. Reads artifacts; deploys nothing.
    function resolve(Overrides memory o, uint256 engineDelay, uint256 engineExpiry)
        internal
        view
        returns (RestrictedSafePlan.Infra memory i)
    {
        bool local = block.chainid == LOCAL_CHAIN_ID;
        i.safeSingleton = _canonical(
            o.safeSingleton,
            block.chainid == ETHEREUM_MAINNET ? SAFE_150 : SAFE_L2_150,
            local,
            type(Safe).creationCode
        );
        i.safeProxyFactory =
            _canonical(o.safeProxyFactory, SAFE_FACTORY_150, local, type(SafeProxyFactory).creationCode);
        i.fallbackHandler = _canonical(
            o.fallbackHandler, FALLBACK_HANDLER_150, local, type(CompatibilityFallbackHandler).creationCode
        );
        i.moduleProxyFactory = _canonical(
            o.moduleProxyFactory, MODULE_PROXY_FACTORY, local, type(ModuleProxyFactory).creationCode
        );

        i.setup = _address(_artifact("RestrictedSafeSetup", "src/factory/RestrictedSafeSetup.sol"));
        i.guard = _address(guardInitCode(engineDelay, engineExpiry));
        i.allowPolicy = _address(_policyEngine("AllowPolicy"));
        i.erc20TransferPolicy = _address(_policyEngine("ERC20TransferPolicy"));
        i.increasedThresholdPolicy = _address(_policyEngine("IncreasedThresholdPolicy"));
        i.approveCapPolicy =
            _address(_artifact("ERC20ApproveCapPolicy", "src/sentinel/ERC20ApproveCapPolicy.sol"));
        i.ownerOnlyPolicy = _address(_artifact("OwnerOnlyPolicy", "src/sentinel/OwnerOnlyPolicy.sol"));
        i.rolesMastercopy = _address(rolesInitCode());
    }

    function guardInitCode(uint256 engineDelay, uint256 engineExpiry) internal view returns (bytes memory) {
        return bytes.concat(_policyEngine("SafePolicyGuard"), abi.encode(engineDelay, engineExpiry));
    }

    /// @dev Roles v2.1.1 linked against the deterministic Integrity and Packer, as an inert mastercopy.
    function rolesInitCode() internal view returns (bytes memory) {
        string memory code = vm.parseJsonString(vm.readFile("out/Roles.sol/Roles.json"), ".bytecode.object");
        code = vm.replace(code, _placeholder(INTEGRITY), _hex(_address(_libraryCode("Integrity"))));
        code = vm.replace(code, _placeholder(PACKER), _hex(_address(_libraryCode("Packer"))));
        return
            bytes.concat(vm.parseBytes(code), abi.encode(address(0xdead), address(0xdead), address(0xdead)));
    }

    /*//////////////////////////////////////////////////////////////
                               DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deploys whatever `i` names that has no code yet, and fails if a canonical contract is
     *         missing. Idempotent. Call inside a broadcast: every deployment is a transaction from the
     *         broadcaster to the CREATE2 deployer.
     */
    function ensure(RestrictedSafePlan.Infra memory i, uint256 engineDelay, uint256 engineExpiry) internal {
        if (block.chainid == LOCAL_CHAIN_ID) {
            _etchIfMissing(CREATE2_DEPLOYER, CREATE2_DEPLOYER_RUNTIME);
            _etchIfMissing(EIP2470_FACTORY, EIP2470_RUNTIME);
            _deploy(i.safeSingleton, type(Safe).creationCode);
            _deploy(i.safeProxyFactory, type(SafeProxyFactory).creationCode);
            _deploy(i.fallbackHandler, type(CompatibilityFallbackHandler).creationCode);
            _deploy(i.moduleProxyFactory, type(ModuleProxyFactory).creationCode);
        }
        require(CREATE2_DEPLOYER.code.length > 0, "CREATE2 deployer 0x4e59b448...56C missing on this chain");
        require(EIP2470_FACTORY.code.length > 0, "EIP-2470 SingletonFactory missing (Zodiac Roles needs it)");
        _requireCode(i.safeSingleton, "Safe v1.5.0 singleton");
        _requireCode(i.safeProxyFactory, "SafeProxyFactory v1.5.0");
        _requireCode(i.fallbackHandler, "fallback handler");
        _requireCode(i.moduleProxyFactory, "Zodiac ModuleProxyFactory");

        _deploy(_libraryCode("Integrity"));
        _deploy(_libraryCode("Packer"));
        _deploy(i.rolesMastercopy, rolesInitCode());
        _deploy(i.setup, _artifact("RestrictedSafeSetup", "src/factory/RestrictedSafeSetup.sol"));
        _deploy(i.guard, guardInitCode(engineDelay, engineExpiry));
        _deploy(i.allowPolicy, _policyEngine("AllowPolicy"));
        _deploy(i.erc20TransferPolicy, _policyEngine("ERC20TransferPolicy"));
        _deploy(i.increasedThresholdPolicy, _policyEngine("IncreasedThresholdPolicy"));
        _deploy(
            i.approveCapPolicy, _artifact("ERC20ApproveCapPolicy", "src/sentinel/ERC20ApproveCapPolicy.sol")
        );
        _deploy(i.ownerOnlyPolicy, _artifact("OwnerOnlyPolicy", "src/sentinel/OwnerOnlyPolicy.sol"));
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _canonical(address overridden, address canonical, bool local, bytes memory localCode)
        private
        pure
        returns (address)
    {
        if (overridden != address(0)) return overridden;
        return local ? _address(localCode) : canonical;
    }

    function _address(bytes memory initCode) private pure returns (address) {
        return vm.computeCreate2Address(SALT, keccak256(initCode), CREATE2_DEPLOYER);
    }

    function _deploy(bytes memory initCode) private {
        _deploy(_address(initCode), initCode);
    }

    function _deploy(address expected, bytes memory initCode) private {
        if (expected.code.length > 0) return;
        (bool ok, bytes memory ret) = CREATE2_DEPLOYER.call(bytes.concat(SALT, initCode));
        require(ok && ret.length == 20 && address(bytes20(ret)) == expected, "CREATE2 deployment failed");
    }

    function _requireCode(address a, string memory what) private view {
        require(
            a.code.length > 0,
            string.concat(
                what, " has no code at ", vm.toString(a), "; set it under `infrastructure` in the config"
            )
        );
    }

    /// @dev Local chains only. In `forge test` the code is etched. On an anvil node it is installed with
    ///      `anvil_setCode`, but forge re-simulates the script on a fork of the block it started from,
    ///      which cannot see that code, so the script stops and asks to be run again.
    function _etchIfMissing(address a, bytes memory runtime) private {
        if (a.code.length > 0) return;
        if (vm.isContext(VmSafe.ForgeContext.TestGroup)) {
            vm.etch(a, runtime);
            return;
        }
        vm.rpc("anvil_setCode", string.concat('["', vm.toString(a), '","', vm.toString(runtime), '"]'));
        revert(
            string.concat(
                "local node: installed the missing ",
                vm.toString(a),
                " (EIP-2470 / CREATE2 deployer); run the command again"
            )
        );
    }

    /// @dev A build artifact's creation code, after checking it was compiled from `source`.
    function _artifact(string memory name, string memory source) private view returns (bytes memory) {
        string memory path = string.concat("out/", name, ".sol/", name, ".json");
        string memory json = vm.readFile(path);
        require(
            vm.keyExistsJson(json, string.concat(".metadata.settings.compilationTarget['", source, "']")),
            string.concat(path, " is not compiled from ", source, "; run `forge build`")
        );
        return vm.parseJsonBytes(json, ".bytecode.object");
    }

    function _policyEngine(string memory name) private view returns (bytes memory) {
        string memory dir = keccak256(bytes(name)) == keccak256("SafePolicyGuard") ? "" : "policies/";
        return _artifact(name, string.concat("node_modules/policy-engine/contracts/", dir, name, ".sol"));
    }

    function _libraryCode(string memory name) private view returns (bytes memory) {
        string memory source = keccak256(bytes(name)) == keccak256("Integrity") ? INTEGRITY : PACKER;
        return _artifact(name, vm.split(source, ":")[0]);
    }

    /// @dev solc's link placeholder: `__$` + the first 17 bytes of keccak256(fully qualified name) + `$__`.
    function _placeholder(string memory fullyQualifiedName) private pure returns (string memory) {
        bytes memory h = bytes(vm.toString(keccak256(bytes(fullyQualifiedName))));
        bytes memory p = new bytes(40);
        p[0] = "_";
        p[1] = "_";
        p[2] = "$";
        for (uint256 k; k < 34; k++) {
            p[3 + k] = h[2 + k];
        }
        p[37] = "$";
        p[38] = "_";
        p[39] = "_";
        return string(p);
    }

    /// @dev 40 lowercase hex characters, no 0x.
    function _hex(address a) private pure returns (string memory) {
        bytes memory s = bytes(vm.toLowercase(vm.toString(a)));
        bytes memory out = new bytes(40);
        for (uint256 k; k < 40; k++) {
            out[k] = s[2 + k];
        }
        return string(out);
    }
}
