// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm } from "forge-std/Vm.sol";
import { RestrictedSafePlan } from "./RestrictedSafePlan.sol";
import { RestrictedSafeInfra } from "./RestrictedSafeInfra.sol";

interface IERC20Decimals {
    function decimals() external view returns (uint8);
}

/**
 * @notice Reads a restricted-Safe configuration file. The format is documented in safe-factory/README.md
 *         and safe-factory/schema.json; safe-factory/examples/ has complete files.
 *
 * Amounts (`maxPerTx`, `maxPerPeriod`, `maxAmount`) are decimal strings in token units, such as "800" or
 * "0.4". They are converted with the token's `decimals()` read from the chain, or with the permission's
 * `decimals` field when it is set (for a token that is not deployed yet).
 */
library RestrictedSafeJson {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant DEFAULT_ENGINE_DELAY = 1 days;
    uint256 internal constant DEFAULT_ENGINE_EXPIRY = 7 days;
    uint256 internal constant DEFAULT_OWNER_SWAP_MAX_ABSENT = 1;

    struct File {
        string name;
        RestrictedSafePlan.Config config;
        RestrictedSafeInfra.Overrides overrides;
    }

    function parse(string memory json) internal view returns (File memory f) {
        f.name = vm.parseJsonString(json, ".name");
        RestrictedSafePlan.Config memory c = f.config;

        c.owners = _addresses(json, ".safe.owners");
        c.threshold = vm.parseJsonUint(json, ".safe.threshold");
        c.saltNonce = _uintOr(json, ".safe.saltNonce", 0);
        c.engineDelay = _uintOr(json, ".policyEngine.delay", DEFAULT_ENGINE_DELAY);
        c.engineExpiry = _uintOr(json, ".policyEngine.expiry", DEFAULT_ENGINE_EXPIRY);
        c.ownerSwapMaxAbsent =
            _uintOr(json, ".policyEngine.ownerSwapMaxAbsent", DEFAULT_OWNER_SWAP_MAX_ABSENT);

        uint256 nRoles = _count(json, ".roles");
        c.roles = new RestrictedSafePlan.Role[](nRoles);
        for (uint256 r; r < nRoles; r++) {
            c.roles[r] = _role(json, string.concat(".roles[", vm.toString(r), "]"));
        }

        uint256 nW = _count(json, ".ownerWithdrawals");
        c.ownerWithdrawals = new RestrictedSafePlan.Withdrawal[](nW);
        for (uint256 w; w < nW; w++) {
            string memory p = string.concat(".ownerWithdrawals[", vm.toString(w), "]");
            c.ownerWithdrawals[w] = RestrictedSafePlan.Withdrawal({
                token: vm.parseJsonAddress(json, string.concat(p, ".token")),
                recipients: _addresses(json, string.concat(p, ".recipients"))
            });
        }

        f.overrides = RestrictedSafeInfra.Overrides({
            safeSingleton: _addressOr(json, ".infrastructure.safeSingleton"),
            safeProxyFactory: _addressOr(json, ".infrastructure.safeProxyFactory"),
            fallbackHandler: _addressOr(json, ".infrastructure.fallbackHandler"),
            moduleProxyFactory: _addressOr(json, ".infrastructure.moduleProxyFactory")
        });
    }

    function _role(string memory json, string memory p)
        private
        view
        returns (RestrictedSafePlan.Role memory role)
    {
        role.name = vm.parseJsonString(json, string.concat(p, ".name"));
        if (vm.keyExistsJson(json, string.concat(p, ".key"))) {
            role.key = vm.parseJsonBytes32(json, string.concat(p, ".key"));
        }
        role.members = _addresses(json, string.concat(p, ".members"));
        uint256 n = _count(json, string.concat(p, ".permissions"));
        role.permissions = new RestrictedSafePlan.Permission[](n);
        for (uint256 i; i < n; i++) {
            role.permissions[i] = _permission(json, string.concat(p, ".permissions[", vm.toString(i), "]"));
        }
    }

    function _permission(string memory json, string memory p)
        private
        view
        returns (RestrictedSafePlan.Permission memory perm)
    {
        string memory kind = vm.parseJsonString(json, string.concat(p, ".kind"));
        bytes32 k = keccak256(bytes(kind));
        if (k == keccak256("call")) {
            perm.kind = RestrictedSafePlan.Kind.Call;
            perm.target = vm.parseJsonAddress(json, string.concat(p, ".target"));
            string[] memory fns = vm.parseJsonStringArray(json, string.concat(p, ".functions"));
            perm.signatures = fns;
            perm.selectors = new bytes4[](fns.length);
            for (uint256 i; i < fns.length; i++) {
                perm.selectors[i] = _selector(fns[i]);
            }
        } else if (k == keccak256("transfer")) {
            perm.kind = RestrictedSafePlan.Kind.Transfer;
            perm.target = vm.parseJsonAddress(json, string.concat(p, ".token"));
            perm.counterparties = _addresses(json, string.concat(p, ".recipients"));
            uint8 d = _decimals(json, p, perm.target);
            perm.maxAmount = _amountOr(json, string.concat(p, ".maxPerTx"), d);
            perm.maxPerPeriod = _amountOr(json, string.concat(p, ".maxPerPeriod"), d);
            perm.period = uint64(_uintOr(json, string.concat(p, ".period"), 0));
        } else if (k == keccak256("approve")) {
            perm.kind = RestrictedSafePlan.Kind.Approve;
            perm.target = vm.parseJsonAddress(json, string.concat(p, ".token"));
            perm.counterparties = _addresses(json, string.concat(p, ".spenders"));
            perm.maxAmount = _amountOr(json, string.concat(p, ".maxAmount"), _decimals(json, p, perm.target));
        } else {
            revert(string.concat(p, ".kind: unknown kind \"", kind, "\" (call, transfer or approve)"));
        }
    }

    /// @dev "commit(bytes32,bytes32)" -> selector. Rejects anything that does not look like a signature.
    function _selector(string memory signature) private pure returns (bytes4) {
        bytes memory s = bytes(signature);
        bool open;
        bool closed;
        for (uint256 i; i < s.length; i++) {
            require(s[i] != " ", string.concat("no spaces in function signatures: ", signature));
            if (s[i] == "(") open = true;
            if (s[i] == ")") closed = true;
        }
        require(
            open && closed && s[s.length - 1] == ")", string.concat("not a function signature: ", signature)
        );
        return bytes4(keccak256(s));
    }

    function _decimals(string memory json, string memory p, address token) private view returns (uint8) {
        string memory key = string.concat(p, ".decimals");
        if (vm.keyExistsJson(json, key)) return uint8(vm.parseJsonUint(json, key));
        require(token.code.length > 0, string.concat(p, ": token has no code; set `decimals` explicitly"));
        return IERC20Decimals(token).decimals();
    }

    /// @dev Decimal string in token units -> base units. Missing key = 0.
    function _amountOr(string memory json, string memory key, uint8 decimals) private view returns (uint256) {
        if (!vm.keyExistsJson(json, key)) return 0;
        return parseUnits(vm.parseJsonString(json, key), decimals);
    }

    function parseUnits(string memory amount, uint8 decimals) internal pure returns (uint256 value) {
        bytes memory s = bytes(amount);
        require(s.length > 0, "empty amount");
        bool dot;
        uint256 fraction;
        for (uint256 i; i < s.length; i++) {
            bytes1 ch = s[i];
            if (ch == ".") {
                require(!dot, string.concat("invalid amount: ", amount));
                dot = true;
                continue;
            }
            require(ch >= "0" && ch <= "9", string.concat("invalid amount (digits and one '.'): ", amount));
            value = value * 10 + (uint8(ch) - 48);
            if (dot) fraction++;
        }
        require(fraction <= decimals, string.concat("more decimals than the token has: ", amount));
        value *= 10 ** (decimals - fraction);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _count(string memory json, string memory key) private view returns (uint256 n) {
        if (!vm.keyExistsJson(json, key)) return 0;
        while (vm.keyExistsJson(json, string.concat(key, "[", vm.toString(n), "]"))) n++;
    }

    /// @dev An address array; missing or empty = [].
    function _addresses(string memory json, string memory key) private view returns (address[] memory a) {
        uint256 n = _count(json, key);
        a = new address[](n);
        for (uint256 i; i < n; i++) {
            a[i] = vm.parseJsonAddress(json, string.concat(key, "[", vm.toString(i), "]"));
        }
    }

    function _uintOr(string memory json, string memory key, uint256 fallback_)
        private
        view
        returns (uint256)
    {
        return vm.keyExistsJson(json, key) ? vm.parseJsonUint(json, key) : fallback_;
    }

    function _addressOr(string memory json, string memory key) private view returns (address) {
        return vm.keyExistsJson(json, key) ? vm.parseJsonAddress(json, key) : address(0);
    }
}
