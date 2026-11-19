// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";
import { VmSafe } from "forge-std/Vm.sol";

import { RestrictedSafePlan } from "./RestrictedSafePlan.sol";
import { RestrictedSafeInfra } from "./RestrictedSafeInfra.sol";
import { RestrictedSafeJson } from "./RestrictedSafeJson.sol";
import { RestrictedSafeCheck } from "./RestrictedSafeCheck.sol";

interface ISafeProxyFactoryCreate {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);

    /// @dev Same address; also emits `ProxyCreationL2(proxy, singleton, initializer, saltNonce)` for indexers.
    function createProxyWithNonceL2(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

/**
 * @notice Deploys a Safe with its owners, Zodiac Roles keys and Safe Policy Engine floor, from one
 *         config file, in one transaction that needs no owner signature. See safe-factory/README.md.
 *
 *   # dry run: prints the Safe address and everything it will be set up with, sends nothing
 *   forge script script/factory/DeployRestrictedSafe.s.sol --sig 'run(string)' safe-factory/my-safe.json \
 *     --rpc-url $RPC_URL
 *
 *   # deploy (any funded account; it gets no rights over the Safe)
 *   forge script ... --rpc-url $RPC_URL --broadcast --account deployer
 *
 * What is sent: the missing shared contracts on first use of a chain (deterministic CREATE2), then
 * `SafeProxyFactory.createProxyWithNonce`. The Safe address depends only on the config, so it is
 * known before deployment and is the same on every chain with the canonical Safe contracts. Running
 * again is safe: an existing Safe is checked, not redeployed.
 *
 * After a broadcast, the record is written to deployments/restricted-safes/<chainId>-<name>.json.
 */
contract DeployRestrictedSafe is Script {
    function run() external returns (address safe, address roles) {
        return run(vm.envString("CONFIG"));
    }

    function run(string memory path) public returns (address safe, address roles) {
        RestrictedSafePlan.Deployment memory d = deploy(path);
        return (d.safe, d.roles);
    }

    /// @notice `run`, returning the full plan (used by the tests).
    function deploy(string memory path) public returns (RestrictedSafePlan.Deployment memory d) {
        RestrictedSafeJson.File memory f = RestrictedSafeJson.parse(vm.readFile(path));
        RestrictedSafePlan.Config memory c = f.config;
        RestrictedSafePlan.Infra memory infra =
            RestrictedSafeInfra.resolve(f.overrides, c.engineDelay, c.engineExpiry);

        vm.startBroadcast();
        RestrictedSafeInfra.ensure(infra, c.engineDelay, c.engineExpiry);
        d = RestrictedSafePlan.plan(c, infra);
        bool existed = d.safe.code.length > 0;
        if (!existed) {
            ISafeProxyFactoryCreate factory = ISafeProxyFactoryCreate(infra.safeProxyFactory);
            address safe = block.chainid == RestrictedSafeInfra.ETHEREUM_MAINNET
                ? factory.createProxyWithNonce(infra.safeSingleton, d.initializer, c.saltNonce)
                : factory.createProxyWithNonceL2(infra.safeSingleton, d.initializer, c.saltNonce);
            require(safe == d.safe, "Safe deployed at an unexpected address");
        }
        vm.stopBroadcast();

        RestrictedSafeCheck.check(c, infra, d);
        bool dryRun = vm.isContext(VmSafe.ForgeContext.ScriptDryRun);
        _report(f, infra, d, existed, dryRun);
        if (!dryRun) _record(f, infra, d);
    }

    /*//////////////////////////////////////////////////////////////
                                 OUTPUT
    //////////////////////////////////////////////////////////////*/

    function _report(
        RestrictedSafeJson.File memory f,
        RestrictedSafePlan.Infra memory infra,
        RestrictedSafePlan.Deployment memory d,
        bool existed,
        bool dryRun
    ) internal pure {
        RestrictedSafePlan.Config memory c = f.config;
        console2.log("");
        console2.log("== Restricted Safe:", f.name);
        if (existed) console2.log("   already deployed: state checked, nothing sent");
        else if (dryRun) console2.log("   DRY RUN: simulated and checked; add --broadcast to deploy");
        else console2.log("   deployed and checked");
        console2.log("Safe            ", d.safe);
        console2.log("Roles module    ", d.roles);
        console2.log("Policy Engine   ", infra.guard);
        console2.log("Safe singleton  ", infra.safeSingleton);
        console2.log(
            string.concat("Owners          ", vm.toString(c.threshold), " of ", vm.toString(c.owners.length))
        );
        for (uint256 i; i < c.owners.length; i++) {
            console2.log("                ", c.owners[i]);
        }
        console2.log(
            string.concat(
                "Engine changes   ",
                vm.toString(c.engineDelay),
                " s delay, applicable for ",
                vm.toString(c.engineExpiry),
                " s"
            )
        );
        for (uint256 r; r < c.roles.length; r++) {
            RestrictedSafePlan.Role memory role = c.roles[r];
            console2.log("");
            console2.log(string.concat("Role ", role.name, "  key ", vm.toString(d.roleKeys[r])));
            for (uint256 m; m < role.members.length; m++) {
                console2.log("  key           ", role.members[m]);
            }
            for (uint256 p; p < role.permissions.length; p++) {
                _logPermission(role.permissions[p]);
            }
        }
        for (uint256 w; w < c.ownerWithdrawals.length; w++) {
            console2.log("");
            console2.log("Owners may transfer token", c.ownerWithdrawals[w].token, "to:");
            for (uint256 i; i < c.ownerWithdrawals[w].recipients.length; i++) {
                console2.log("               ", c.ownerWithdrawals[w].recipients[i]);
            }
        }
        console2.log("");
        console2.log(
            string.concat(
                "Policy Engine entries: ",
                vm.toString(d.setup.entries.length),
                " mandate + 9 admin (owner-only Roles admin, disableModule, swapOwner)"
            )
        );
        console2.log("A key acts by calling, on the Roles module:");
        console2.log("  execTransactionWithRole(to, 0, data, 0, roleKey, true)");
    }

    function _logPermission(RestrictedSafePlan.Permission memory p) internal pure {
        if (p.kind == RestrictedSafePlan.Kind.Call) {
            console2.log("  call          ", p.target);
            for (uint256 s; s < p.selectors.length; s++) {
                string memory sig = s < p.signatures.length ? p.signatures[s] : "";
                console2.log(
                    string.concat(
                        "    function     ", vm.toString(abi.encodePacked(p.selectors[s])), " ", sig
                    )
                );
            }
        } else if (p.kind == RestrictedSafePlan.Kind.Transfer) {
            console2.log("  transfer token", p.target);
            for (uint256 i; i < p.counterparties.length; i++) {
                console2.log("    to          ", p.counterparties[i]);
            }
            if (p.maxAmount > 0) console2.log("    max per tx   (base units)", p.maxAmount);
            if (p.maxPerPeriod > 0) {
                console2.log("    max per period (base units)", p.maxPerPeriod);
                console2.log("    period (s)  ", uint256(p.period));
            }
        } else {
            console2.log("  approve token ", p.target);
            for (uint256 i; i < p.counterparties.length; i++) {
                console2.log("    spender     ", p.counterparties[i]);
            }
            console2.log("    max amount   (base units)", p.maxAmount);
        }
    }

    function _record(
        RestrictedSafeJson.File memory f,
        RestrictedSafePlan.Infra memory infra,
        RestrictedSafePlan.Deployment memory d
    ) internal {
        string memory o = "restricted-safe";
        vm.serializeString(o, "name", f.name);
        vm.serializeUint(o, "chainId", block.chainid);
        vm.serializeAddress(o, "safe", d.safe);
        vm.serializeAddress(o, "roles", d.roles);
        vm.serializeAddress(o, "policyGuard", infra.guard);
        vm.serializeAddress(o, "setup", infra.setup);
        vm.serializeAddress(o, "safeSingleton", infra.safeSingleton);
        vm.serializeAddress(o, "owners", f.config.owners);
        vm.serializeUint(o, "threshold", f.config.threshold);
        vm.serializeBytes32(o, "roleKeys", d.roleKeys);
        vm.serializeBytes(o, "safeSetupCalldata", d.initializer);
        string memory json = vm.serializeUint(o, "saltNonce", f.config.saltNonce);
        vm.createDir("deployments/restricted-safes", true);
        vm.writeJson(
            json,
            string.concat("deployments/restricted-safes/", vm.toString(block.chainid), "-", f.name, ".json")
        );
    }
}
