// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { RestrictedSafeSetup } from "../../src/factory/RestrictedSafeSetup.sol";

interface ISafeProxyFactoryView {
    function proxyCreationCode() external view returns (bytes memory);
}

/**
 * @notice Turns a restricted-Safe configuration into the one `createProxyWithNonce` call that deploys
 *         it. The translation is pure and auditable: no chain access except reading the Safe proxy
 *         creation code and the Roles address formula from the deployed contracts.
 *
 * Every permission gives its role an exact Zodiac Roles scope, AND adds the matching Safe Policy Engine
 * entry (the floor, which also holds if Roles is misconfigured or compromised):
 *
 *   kind       Roles scope (per role)                         Policy Engine entry (per Safe)
 *   call       allowFunction(target, selector) per function   AllowPolicy
 *   transfer   token.transfer(to, amount):                     ERC20TransferPolicy: recipients
 *                to in recipients, amount <= maxPerTx,
 *                amount within the per-period allowance
 *   approve    token.approve(spender, amount):                 ERC20ApproveCapPolicy: spenders, cap
 *                spender in spenders, amount <= maxAmount
 *
 * The engine is keyed by (target, selector), not by role, so its entry is the union over all roles:
 * recipients and spenders are merged and an approve cap is the highest one. Each role is still held to
 * its own Roles scope. `ownerWithdrawals` adds transfer recipients to the engine only (no role).
 */
library RestrictedSafePlan {
    enum Kind {
        Call,
        Transfer,
        Approve
    }

    struct Permission {
        Kind kind;
        address target; // the contract (call) or the token (transfer, approve)
        bytes4[] selectors; // call: the functions
        string[] signatures; // call: the same functions, as written in the config (for display only)
        address[] counterparties; // transfer: recipients; approve: spenders
        uint256 maxAmount; // transfer: per transaction (0 = no cap); approve: required cap
        uint256 maxPerPeriod; // transfer: allowance per period (0 = none)
        uint64 period; // transfer: allowance period in seconds
    }

    struct Role {
        string name;
        bytes32 key; // 0: derived from the name (Zodiac convention: the name as bytes32)
        address[] members;
        Permission[] permissions;
    }

    struct Withdrawal {
        address token;
        address[] recipients;
    }

    struct Config {
        address[] owners;
        uint256 threshold;
        uint256 saltNonce;
        uint256 engineDelay; // seconds between requesting and applying a Policy Engine change
        uint256 engineExpiry; // seconds a requested change stays applicable
        uint256 ownerSwapMaxAbsent; // Safe.swapOwner needs all owners but this many (and > threshold)
        Role[] roles;
        Withdrawal[] ownerWithdrawals;
    }

    /// @dev Contracts the Safe is built from. All must have code on the target chain.
    struct Infra {
        address safeSingleton;
        address safeProxyFactory;
        address fallbackHandler;
        address moduleProxyFactory;
        address rolesMastercopy;
        address setup; // RestrictedSafeSetup
        address guard; // SafePolicyGuard(engineDelay, engineExpiry)
        address allowPolicy;
        address erc20TransferPolicy;
        address approveCapPolicy; // ERC20ApproveCapPolicy
        address ownerOnlyPolicy;
        address increasedThresholdPolicy;
    }

    struct Deployment {
        address safe; // predicted
        address roles; // predicted
        bytes initializer; // Safe.setup calldata
        RestrictedSafeSetup.Setup setup;
        bytes32[] roleKeys; // per config role
        bytes32[] allowanceKeys; // per config role and permission (0 when none), flattened
    }

    // Selectors
    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 internal constant TRANSFER_FROM = bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 internal constant APPROVE = bytes4(keccak256("approve(address,uint256)"));
    bytes4 internal constant INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));
    bytes4 internal constant SCOPE_TARGET = bytes4(keccak256("scopeTarget(bytes32,address)"));
    bytes4 internal constant SCOPE_FUNCTION =
        bytes4(keccak256("scopeFunction(bytes32,address,bytes4,(uint8,uint8,uint8,bytes)[],uint8)"));
    bytes4 internal constant ALLOW_FUNCTION =
        bytes4(keccak256("allowFunction(bytes32,address,bytes4,uint8)"));
    bytes4 internal constant SET_ALLOWANCE =
        bytes4(keccak256("setAllowance(bytes32,uint128,uint128,uint128,uint64,uint64)"));

    // Zodiac Roles v2.1.1 enums (Types.sol), as numbers so this file compiles no LGPL source.
    uint8 internal constant PT_NONE = 0;
    uint8 internal constant PT_STATIC = 1;
    uint8 internal constant PT_CALLDATA = 5;
    uint8 internal constant OP_PASS = 0;
    uint8 internal constant OP_AND = 1;
    uint8 internal constant OP_OR = 2;
    uint8 internal constant OP_MATCHES = 5;
    uint8 internal constant OP_EQUAL_TO = 16;
    uint8 internal constant OP_LESS_THAN = 18;
    uint8 internal constant OP_WITHIN_ALLOWANCE = 28;

    /// @dev ABI-identical to Zodiac Roles `ConditionFlat`.
    struct Condition {
        uint8 parent;
        uint8 paramType;
        uint8 operator;
        bytes compValue;
    }

    /// @dev Policy Engine `ERC20TransferPolicy.RecipientData` (Permission 2 = ALWAYS).
    struct RecipientData {
        address recipient;
        uint8 permission;
    }

    /// @dev `ERC20ApproveCapPolicy.SpenderCap`.
    struct SpenderCap {
        address spender;
        bool allowed;
        uint248 maxAmount;
    }

    /*//////////////////////////////////////////////////////////////
                                  PLAN
    //////////////////////////////////////////////////////////////*/

    function plan(Config memory c, Infra memory infra) internal view returns (Deployment memory d) {
        validate(c);

        d.roleKeys = new bytes32[](c.roles.length);
        uint256 permissionCount;
        for (uint256 r; r < c.roles.length; r++) {
            d.roleKeys[r] = roleKey(c.roles[r]);
            for (uint256 s; s < r; s++) {
                require(d.roleKeys[s] != d.roleKeys[r], string.concat("duplicate role: ", c.roles[r].name));
            }
            permissionCount += c.roles[r].permissions.length;
        }

        bytes[] memory calls = new bytes[](0);
        d.allowanceKeys = new bytes32[](permissionCount);
        uint256 flat;
        for (uint256 r; r < c.roles.length; r++) {
            bytes[] memory roleCalls;
            (roleCalls, flat) = _roleCalls(c.roles[r], d.roleKeys[r], d.allowanceKeys, flat);
            calls = _concat(calls, roleCalls);
        }

        d.setup = RestrictedSafeSetup.Setup({
            rolesMastercopy: infra.rolesMastercopy,
            moduleProxyFactory: infra.moduleProxyFactory,
            rolesCalls: calls,
            members: _members(c, d.roleKeys),
            guard: infra.guard,
            ownerOnlyPolicy: infra.ownerOnlyPolicy,
            increasedThresholdPolicy: infra.increasedThresholdPolicy,
            ownerSwapMaxAbsent: c.ownerSwapMaxAbsent,
            entries: engineEntries(c, infra)
        });

        d.initializer = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            c.owners,
            c.threshold,
            infra.setup,
            abi.encodeCall(RestrictedSafeSetup.setUp, (d.setup)),
            infra.fallbackHandler,
            address(0),
            uint256(0),
            address(0)
        );
        d.safe = predictSafe(infra, d.initializer, c.saltNonce);
        d.roles = RestrictedSafeSetup(infra.setup)
            .rolesAddress(d.safe, infra.moduleProxyFactory, infra.rolesMastercopy);
    }

    /// @notice SafeProxyFactory v1.5.0 `createProxyWithNonce` address.
    function predictSafe(Infra memory infra, bytes memory initializer, uint256 saltNonce)
        internal
        view
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        bytes32 codeHash = keccak256(
            abi.encodePacked(
                ISafeProxyFactoryView(infra.safeProxyFactory).proxyCreationCode(),
                uint256(uint160(infra.safeSingleton))
            )
        );
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), infra.safeProxyFactory, salt, codeHash)))
            )
        );
    }

    /// @notice The role key: explicit, or the Zodiac convention (UTF-8 name, left-aligned, zero-padded).
    function roleKey(Role memory role) internal pure returns (bytes32) {
        if (role.key != bytes32(0)) return role.key;
        bytes memory n = bytes(role.name);
        require(n.length > 0 && n.length <= 31, "role name must be 1 to 31 bytes");
        return bytes32(n);
    }

    function allowanceKey(bytes32 role, address token) internal pure returns (bytes32) {
        return keccak256(abi.encode("restricted-safe.transfer-allowance", role, token));
    }

    /*//////////////////////////////////////////////////////////////
                               VALIDATION
    //////////////////////////////////////////////////////////////*/

    function validate(Config memory c) internal pure {
        require(c.owners.length > 0, "no owners");
        for (uint256 i; i < c.owners.length; i++) {
            require(c.owners[i] != address(0) && c.owners[i] != address(0x1), "invalid owner address");
            _requireNotPlaceholder(c.owners[i]);
            for (uint256 j; j < i; j++) {
                require(c.owners[i] != c.owners[j], "duplicate owner");
            }
        }
        require(c.threshold >= 1 && c.threshold <= c.owners.length, "threshold must be 1..owners");
        require(c.engineExpiry > 0, "policyEngine.expiry must be > 0");
        require(c.roles.length > 0, "no roles");

        for (uint256 r; r < c.roles.length; r++) {
            Role memory role = c.roles[r];
            require(role.permissions.length > 0, string.concat("role has no permissions: ", role.name));
            for (uint256 m; m < role.members.length; m++) {
                require(role.members[m] != address(0), string.concat("zero member in role ", role.name));
                _requireNotPlaceholder(role.members[m]);
                for (uint256 o; o < c.owners.length; o++) {
                    require(role.members[m] != c.owners[o], "an operational key must not be a Safe owner");
                }
            }
            for (uint256 p; p < role.permissions.length; p++) {
                _validatePermission(role.name, role.permissions[p]);
                for (uint256 q; q < p; q++) {
                    _requireNoOverlap(role.name, role.permissions[p], role.permissions[q]);
                }
            }
        }
        for (uint256 w; w < c.ownerWithdrawals.length; w++) {
            require(c.ownerWithdrawals[w].token != address(0), "withdrawal token is zero");
            _requireNonZero(c.ownerWithdrawals[w].recipients, "withdrawal recipients");
        }
    }

    function _validatePermission(string memory role, Permission memory p) private pure {
        string memory where = string.concat(" (role ", role, ")");
        require(p.target != address(0), string.concat("permission target is zero", where));
        if (p.kind == Kind.Call) {
            require(p.selectors.length > 0, string.concat("call permission without functions", where));
            for (uint256 i; i < p.selectors.length; i++) {
                bytes4 s = p.selectors[i];
                require(
                    s != TRANSFER && s != TRANSFER_FROM && s != APPROVE && s != INCREASE_ALLOWANCE,
                    string.concat("use a transfer or approve permission for token movements", where)
                );
                for (uint256 j; j < i; j++) {
                    require(p.selectors[j] != s, string.concat("duplicate function", where));
                }
            }
        } else if (p.kind == Kind.Transfer) {
            _requireNonZero(p.counterparties, string.concat("transfer recipients", where));
            require(p.maxAmount < type(uint256).max, string.concat("maxPerTx too large", where));
            if (p.maxPerPeriod > 0) {
                require(p.period > 0, string.concat("maxPerPeriod needs a period", where));
                require(p.maxPerPeriod <= type(uint128).max, string.concat("maxPerPeriod too large", where));
            }
        } else {
            _requireNonZero(p.counterparties, string.concat("approve spenders", where));
            require(
                p.maxAmount > 0 && p.maxAmount <= type(uint248).max,
                string.concat("approve needs a maxAmount (and at most 2^248 - 1)", where)
            );
        }
    }

    /// @dev Roles has one scope per (target, selector) per role: two permissions may not share one.
    function _requireNoOverlap(string memory role, Permission memory a, Permission memory b) private pure {
        if (a.target != b.target) return;
        bytes4[] memory sa = _selectors(a);
        bytes4[] memory sb = _selectors(b);
        for (uint256 i; i < sa.length; i++) {
            for (uint256 j; j < sb.length; j++) {
                require(
                    sa[i] != sb[j],
                    string.concat(
                        "role ",
                        role,
                        ": two permissions cover the same function on the same target; merge them into one"
                    )
                );
            }
        }
    }

    function _requireNonZero(address[] memory list, string memory what) private pure {
        require(list.length > 0, string.concat(what, ": empty"));
        for (uint256 i; i < list.length; i++) {
            require(list[i] != address(0), string.concat(what, ": zero address"));
            _requireNotPlaceholder(list[i]);
            for (uint256 j; j < i; j++) {
                require(list[i] != list[j], string.concat(what, ": duplicate"));
            }
        }
    }

    /// @dev The example configs use 0x1111...1111-style placeholders: refuse to deploy one by mistake.
    function _requireNotPlaceholder(address a) private pure {
        uint160 v = uint160(a);
        uint160 nibble = v & 0xf;
        bool repeated = nibble != 0;
        for (uint256 i; i < 40 && repeated; i++) {
            repeated = (v >> (4 * i)) & 0xf == nibble;
        }
        require(!repeated, "placeholder address (0x1111...-style) in the config: replace it before deploying");
    }

    /*//////////////////////////////////////////////////////////////
                             ZODIAC ROLES
    //////////////////////////////////////////////////////////////*/

    function _roleCalls(Role memory role, bytes32 key, bytes32[] memory allowanceKeys, uint256 flat)
        private
        pure
        returns (bytes[] memory calls, uint256)
    {
        // scopeTarget once per distinct target, then the functions
        address[] memory targets = new address[](role.permissions.length);
        uint256 nTargets;
        uint256 nCalls;
        for (uint256 p; p < role.permissions.length; p++) {
            Permission memory perm = role.permissions[p];
            bool seen;
            for (uint256 t; t < nTargets; t++) {
                if (targets[t] == perm.target) seen = true;
            }
            if (!seen) targets[nTargets++] = perm.target;
            nCalls += perm.kind == Kind.Call ? perm.selectors.length : (perm.maxPerPeriod > 0 ? 2 : 1);
        }
        calls = new bytes[](nTargets + nCalls);
        uint256 k;
        for (uint256 t; t < nTargets; t++) {
            calls[k++] = abi.encodeWithSelector(SCOPE_TARGET, key, targets[t]);
        }
        for (uint256 p; p < role.permissions.length; p++) {
            Permission memory perm = role.permissions[p];
            if (perm.kind == Kind.Call) {
                for (uint256 s; s < perm.selectors.length; s++) {
                    calls[k++] =
                        abi.encodeWithSelector(ALLOW_FUNCTION, key, perm.target, perm.selectors[s], uint8(0));
                }
            } else if (perm.kind == Kind.Transfer) {
                bytes32 aKey = perm.maxPerPeriod > 0 ? allowanceKey(key, perm.target) : bytes32(0);
                allowanceKeys[flat] = aKey;
                calls[k++] = abi.encodeWithSelector(
                    SCOPE_FUNCTION,
                    key,
                    perm.target,
                    TRANSFER,
                    addressAmountScope(perm.counterparties, perm.maxAmount, aKey),
                    uint8(0)
                );
                if (aKey != bytes32(0)) {
                    // balance = maxRefill = refill = maxPerPeriod; timestamp 0 = now
                    calls[k++] = abi.encodeWithSelector(
                        SET_ALLOWANCE,
                        aKey,
                        uint128(perm.maxPerPeriod),
                        uint128(perm.maxPerPeriod),
                        uint128(perm.maxPerPeriod),
                        perm.period,
                        uint64(0)
                    );
                }
            } else {
                calls[k++] = abi.encodeWithSelector(
                    SCOPE_FUNCTION,
                    key,
                    perm.target,
                    APPROVE,
                    addressAmountScope(perm.counterparties, perm.maxAmount, bytes32(0)),
                    uint8(0)
                );
            }
            flat++;
        }
        return (calls, flat);
    }

    /**
     * Roles conditions for `f(address who, uint256 amount)`:
     *   who    == the one address, or Or(EqualTo each)
     *   amount  < maxAmount + 1 (if maxAmount > 0), within allowance `aKey` (if set), both (And), or any
     */
    function addressAmountScope(address[] memory who, uint256 maxAmount, bytes32 aKey)
        internal
        pure
        returns (Condition[] memory c)
    {
        bool many = who.length > 1;
        bool cap = maxAmount > 0;
        bool allowance = aKey != bytes32(0);
        bool both = cap && allowance;
        c = new Condition[](3 + (many ? who.length : 0) + (both ? 2 : 0));
        c[0] = Condition(0, PT_CALLDATA, OP_MATCHES, "");
        c[1] = many
            ? Condition(0, PT_NONE, OP_OR, "")
            : Condition(0, PT_STATIC, OP_EQUAL_TO, abi.encode(who[0]));
        if (both) c[2] = Condition(0, PT_NONE, OP_AND, "");
        else if (cap) c[2] = Condition(0, PT_STATIC, OP_LESS_THAN, abi.encode(maxAmount + 1));
        else if (allowance) c[2] = Condition(0, PT_STATIC, OP_WITHIN_ALLOWANCE, abi.encode(aKey));
        else c[2] = Condition(0, PT_STATIC, OP_PASS, "");
        uint256 k = 3;
        if (many) {
            for (uint256 i; i < who.length; i++) {
                c[k++] = Condition(1, PT_STATIC, OP_EQUAL_TO, abi.encode(who[i]));
            }
        }
        if (both) {
            c[k++] = Condition(2, PT_STATIC, OP_LESS_THAN, abi.encode(maxAmount + 1));
            c[k++] = Condition(2, PT_STATIC, OP_WITHIN_ALLOWANCE, abi.encode(aKey));
        }
    }

    /// @dev One Member per distinct account, with every role it is listed in.
    function _members(Config memory c, bytes32[] memory keys)
        private
        pure
        returns (RestrictedSafeSetup.Member[] memory out)
    {
        address[] memory accounts = new address[](0);
        for (uint256 r; r < c.roles.length; r++) {
            for (uint256 m; m < c.roles[r].members.length; m++) {
                if (!_contains(accounts, c.roles[r].members[m])) {
                    accounts = _push(accounts, c.roles[r].members[m]);
                }
            }
        }
        out = new RestrictedSafeSetup.Member[](accounts.length);
        for (uint256 a; a < accounts.length; a++) {
            uint256 n;
            for (uint256 r; r < c.roles.length; r++) {
                if (_contains(c.roles[r].members, accounts[a])) n++;
            }
            bytes32[] memory memberKeys = new bytes32[](n);
            n = 0;
            for (uint256 r; r < c.roles.length; r++) {
                if (_contains(c.roles[r].members, accounts[a])) memberKeys[n++] = keys[r];
            }
            out[a] = RestrictedSafeSetup.Member(accounts[a], memberKeys);
        }
    }

    /*//////////////////////////////////////////////////////////////
                           SAFE POLICY ENGINE
    //////////////////////////////////////////////////////////////*/

    struct Draft {
        address target;
        bytes4 selector;
        Kind kind;
        address[] counterparties;
        uint256[] caps; // approve only, per counterparty
    }

    /// @notice The mandate entries (the setup contract adds the admin entries).
    function engineEntries(Config memory c, Infra memory infra)
        internal
        pure
        returns (RestrictedSafeSetup.EngineEntry[] memory e)
    {
        Draft[] memory drafts = new Draft[](0);
        for (uint256 r; r < c.roles.length; r++) {
            for (uint256 p; p < c.roles[r].permissions.length; p++) {
                Permission memory perm = c.roles[r].permissions[p];
                if (perm.kind == Kind.Call) {
                    for (uint256 s; s < perm.selectors.length; s++) {
                        drafts =
                            _merge(drafts, perm.target, perm.selectors[s], Kind.Call, new address[](0), 0);
                    }
                } else if (perm.kind == Kind.Transfer) {
                    drafts = _merge(drafts, perm.target, TRANSFER, Kind.Transfer, perm.counterparties, 0);
                } else {
                    drafts = _merge(
                        drafts, perm.target, APPROVE, Kind.Approve, perm.counterparties, perm.maxAmount
                    );
                }
            }
        }
        for (uint256 w; w < c.ownerWithdrawals.length; w++) {
            drafts = _merge(
                drafts,
                c.ownerWithdrawals[w].token,
                TRANSFER,
                Kind.Transfer,
                c.ownerWithdrawals[w].recipients,
                0
            );
        }

        e = new RestrictedSafeSetup.EngineEntry[](drafts.length);
        for (uint256 i; i < drafts.length; i++) {
            Draft memory d = drafts[i];
            if (d.kind == Kind.Call) {
                e[i] = RestrictedSafeSetup.EngineEntry(d.target, d.selector, 0, infra.allowPolicy, "");
            } else if (d.kind == Kind.Transfer) {
                RecipientData[] memory data = new RecipientData[](d.counterparties.length);
                for (uint256 j; j < data.length; j++) {
                    data[j] = RecipientData(d.counterparties[j], 2);
                }
                e[i] = RestrictedSafeSetup.EngineEntry(
                    d.target, d.selector, 0, infra.erc20TransferPolicy, abi.encode(data)
                );
            } else {
                SpenderCap[] memory data = new SpenderCap[](d.counterparties.length);
                for (uint256 j; j < data.length; j++) {
                    data[j] = SpenderCap(d.counterparties[j], true, uint248(d.caps[j]));
                }
                e[i] = RestrictedSafeSetup.EngineEntry(
                    d.target, d.selector, 0, infra.approveCapPolicy, abi.encode(data)
                );
            }
        }
    }

    function _merge(
        Draft[] memory drafts,
        address target,
        bytes4 selector,
        Kind kind,
        address[] memory counterparties,
        uint256 cap
    ) private pure returns (Draft[] memory) {
        uint256 i;
        for (; i < drafts.length; i++) {
            if (drafts[i].target == target && drafts[i].selector == selector) break;
        }
        if (i == drafts.length) {
            Draft[] memory grown = new Draft[](drafts.length + 1);
            for (uint256 j; j < drafts.length; j++) {
                grown[j] = drafts[j];
            }
            grown[i] = Draft(target, selector, kind, new address[](0), new uint256[](0));
            drafts = grown;
        }
        require(drafts[i].kind == kind, "the same function is granted with two different permission kinds");
        for (uint256 k; k < counterparties.length; k++) {
            uint256 at = _indexOf(drafts[i].counterparties, counterparties[k]);
            if (at == type(uint256).max) {
                drafts[i].counterparties = _push(drafts[i].counterparties, counterparties[k]);
                drafts[i].caps = _pushUint(drafts[i].caps, cap);
            } else if (cap > drafts[i].caps[at]) {
                drafts[i].caps[at] = cap; // the floor is the union: the highest cap of any role
            }
        }
        return drafts;
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function _selectors(Permission memory p) private pure returns (bytes4[] memory s) {
        if (p.kind == Kind.Call) return p.selectors;
        s = new bytes4[](1);
        s[0] = p.kind == Kind.Transfer ? TRANSFER : APPROVE;
    }

    function _indexOf(address[] memory list, address a) private pure returns (uint256) {
        for (uint256 i; i < list.length; i++) {
            if (list[i] == a) return i;
        }
        return type(uint256).max;
    }

    function _contains(address[] memory list, address a) private pure returns (bool) {
        return _indexOf(list, a) != type(uint256).max;
    }

    function _push(address[] memory list, address a) private pure returns (address[] memory out) {
        out = new address[](list.length + 1);
        for (uint256 i; i < list.length; i++) {
            out[i] = list[i];
        }
        out[list.length] = a;
    }

    function _pushUint(uint256[] memory list, uint256 v) private pure returns (uint256[] memory out) {
        out = new uint256[](list.length + 1);
        for (uint256 i; i < list.length; i++) {
            out[i] = list[i];
        }
        out[list.length] = v;
    }

    function _concat(bytes[] memory a, bytes[] memory b) private pure returns (bytes[] memory c) {
        c = new bytes[](a.length + b.length);
        for (uint256 i; i < a.length; i++) {
            c[i] = a[i];
        }
        for (uint256 i; i < b.length; i++) {
            c[a.length + i] = b[i];
        }
    }
}
