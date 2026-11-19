// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Safe v1.5.0 functions used during setup (MIT declaration, ABI-identical to upstream).
interface ISafeSetupTarget {
    function nonce() external view returns (uint256);
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
    function enableModule(address module) external;
    function setGuard(address guard) external;
    function setModuleGuard(address guard) external;
}

/// @dev Zodiac ModuleProxyFactory (MIT declaration, ABI-identical to upstream).
interface IModuleProxyFactory {
    function deployModule(address masterCopy, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

/// @dev Zodiac Roles v2 functions used during setup (MIT declaration, ABI-identical to upstream).
interface IRolesSetup {
    function owner() external view returns (address);
    function avatar() external view returns (address);
    function target() external view returns (address);
    function assignRoles(address module, bytes32[] calldata roleKeys, bool[] calldata memberOf) external;
}

/**
 * @title RestrictedSafeSetup
 * @notice Sets up a new Safe v1.5.0 in the transaction that creates it: Zodiac Roles for the
 *         operational keys, and Safe Policy Engine as both guards. Nobody signs anything, and there is no
 *         moment when the Safe exists without its restrictions.
 *
 * Pass this contract as `to` and `abi.encodeCall(RestrictedSafeSetup.setUp, (setup))` as `data` in
 * `Safe.setup`. The Safe delegatecalls it once, before it has any state of its own. This code then runs as
 * the Safe, so every call below is made with `msg.sender == safe`, exactly like an owner transaction:
 *
 *   1. deploy a Roles proxy owned by the Safe (owner = avatar = target = Safe), and enable it as module
 *   2. apply the role permissions (scopeTarget / scopeFunction / allowFunction / setAllowance only)
 *   3. assign the operational keys to their roles
 *   4. configure the Policy Engine: the admin entries below plus the mandate entries from `setup`
 *   5. install the engine as module guard, then as transaction guard
 *
 * If any step fails, `Safe.setup` reverts and the Safe is not created.
 *
 * Invariants enforced here, whatever the caller passes:
 *   - Runs only as a delegatecall from a Safe that is still being set up (nonce 0, no module).
 *   - Role permissions never send ETH value, never delegatecall and never allow a whole target
 *     (`allowTarget` is not accepted). They never name the Safe, Roles or the guard as target.
 *   - Mandate entries are CALL-only, have a policy, and never target the Safe, Roles or the guard.
 *     Calls to those three are governed by the admin entries only.
 *   - The admin entries are always installed, so the owners keep control once default-deny is on:
 *       Roles.assignRoles, scopeTarget, scopeFunction, allowFunction,
 *             revokeTarget, revokeFunction, setAllowance          OwnerOnlyPolicy (never a module)
 *       Safe.disableModule                                         OwnerOnlyPolicy (kill switch)
 *       Safe.swapOwner                                             IncreasedThresholdPolicy
 *     Anything else, such as adding a module, changing the threshold or removing the guard, needs a
 *     Policy Engine change: `requestConfiguration`, the engine delay, then `applyConfiguration`.
 *
 * Stateless and permissionless: one deployment per chain serves every Safe.
 */
contract RestrictedSafeSetup {
    /// @dev ABI of `SafePolicyGuard.Configuration` (safe-research/policy-engine).
    struct EngineEntry {
        address target;
        bytes4 selector;
        uint8 operation; // 0 CALL, 1 DELEGATECALL
        address policy;
        bytes data;
    }

    struct Member {
        address account;
        bytes32[] roleKeys;
    }

    struct Setup {
        address rolesMastercopy; // Zodiac Roles v2.1.1 mastercopy
        address moduleProxyFactory; // Zodiac ModuleProxyFactory
        bytes[] rolesCalls; // calldata for the new Roles proxy, each called by the Safe
        Member[] members; // operational keys and their roles
        address guard; // SafePolicyGuard
        address ownerOnlyPolicy;
        address increasedThresholdPolicy;
        uint256 ownerSwapMaxAbsent; // IncreasedThresholdPolicy data for Safe.swapOwner
        EngineEntry[] entries; // the mandate floor (admin entries are added here)
    }

    // Safe v1.5.0
    bytes4 internal constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));
    bytes4 internal constant DISABLE_MODULE = bytes4(keccak256("disableModule(address,address)"));
    address internal constant SENTINEL_MODULES = address(0x1);
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant MODULE_GUARD_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    // Zodiac Roles v2.1.1
    bytes4 internal constant ROLES_SETUP = bytes4(keccak256("setUp(bytes)"));
    bytes4 internal constant ASSIGN_ROLES = bytes4(keccak256("assignRoles(address,bytes32[],bool[])"));
    bytes4 internal constant SCOPE_TARGET = bytes4(keccak256("scopeTarget(bytes32,address)"));
    bytes4 internal constant SCOPE_FUNCTION =
        bytes4(keccak256("scopeFunction(bytes32,address,bytes4,(uint8,uint8,uint8,bytes)[],uint8)"));
    bytes4 internal constant ALLOW_FUNCTION =
        bytes4(keccak256("allowFunction(bytes32,address,bytes4,uint8)"));
    bytes4 internal constant REVOKE_TARGET = bytes4(keccak256("revokeTarget(bytes32,address)"));
    bytes4 internal constant REVOKE_FUNCTION = bytes4(keccak256("revokeFunction(bytes32,address,bytes4)"));
    bytes4 internal constant SET_ALLOWANCE =
        bytes4(keccak256("setAllowance(bytes32,uint128,uint128,uint128,uint64,uint64)"));

    /// @dev The Roles proxy's salt nonce. Its initializer names the Safe, so the address is unique anyway.
    uint256 internal constant ROLES_SALT_NONCE = 0;

    address private immutable SELF;

    /// @notice Emitted by the Safe (this code runs in its context) once it is fully set up.
    event RestrictedSafeSetUp(address indexed roles, address indexed guard, uint256 members, uint256 entries);

    error OnlyDelegateCall();
    error OnlyDuringSafeSetup();
    error NoCode(address account);
    error RolesProxyMisconfigured(address roles);
    error RolesCallNotAllowed(uint256 index, bytes4 selector);
    error RolesCallTargetNotAllowed(uint256 index, address target);
    error RolesCallOptionsNotAllowed(uint256 index, uint256 options);
    error RolesCallFailed(uint256 index, bytes reason);
    error InvalidMember(address account);
    error EntryNotAllowed(uint256 index, address target, bytes4 selector);

    constructor() {
        SELF = address(this);
    }

    /// @notice Delegatecalled by `Safe.setup`. See the contract documentation.
    function setUp(Setup calldata s) external {
        address safe = address(this);
        require(safe != SELF, OnlyDelegateCall());
        _requireSafeBeingSetUp();
        _requireCode(s.rolesMastercopy);
        _requireCode(s.moduleProxyFactory);
        _requireCode(s.guard);
        _requireCode(s.ownerOnlyPolicy);
        _requireCode(s.increasedThresholdPolicy);

        // 1. Roles, owned by the Safe
        address roles = _deployRoles(safe, s.moduleProxyFactory, s.rolesMastercopy);
        ISafeSetupTarget(safe).enableModule(roles);

        // 2. permissions, 3. members
        for (uint256 i; i < s.rolesCalls.length; i++) {
            _checkRolesCall(i, s.rolesCalls[i], safe, roles, s.guard);
            (bool ok, bytes memory reason) = roles.call(s.rolesCalls[i]);
            require(ok, RolesCallFailed(i, reason));
        }
        for (uint256 i; i < s.members.length; i++) {
            address account = s.members[i].account;
            require(
                account != address(0) && account != safe && account != roles && account != s.guard,
                InvalidMember(account)
            );
            bool[] memory memberOf = new bool[](s.members[i].roleKeys.length);
            for (uint256 j; j < memberOf.length; j++) {
                memberOf[j] = true;
            }
            IRolesSetup(roles).assignRoles(account, s.members[i].roleKeys, memberOf);
        }

        // 4. engine entries: admin first, then the mandate
        EngineEntry[] memory admin = adminEntries(safe, roles, s);
        EngineEntry[] memory all = new EngineEntry[](admin.length + s.entries.length);
        for (uint256 i; i < admin.length; i++) {
            all[i] = admin[i];
        }
        for (uint256 i; i < s.entries.length; i++) {
            EngineEntry calldata e = s.entries[i];
            require(
                e.operation == 0 && e.policy != address(0) && e.target != address(0) && e.target != safe
                    && e.target != roles && e.target != s.guard,
                EntryNotAllowed(i, e.target, e.selector)
            );
            all[admin.length + i] = e;
        }
        (bool configured, bytes memory configureReason) = s.guard
            .call(
                abi.encodeWithSignature("configureImmediately((address,bytes4,uint8,address,bytes)[])", all)
            );
        if (!configured) _bubble(configureReason);

        // 5. guards: the module guard first, then the transaction guard
        ISafeSetupTarget(safe).setModuleGuard(s.guard);
        ISafeSetupTarget(safe).setGuard(s.guard);

        emit RestrictedSafeSetUp(roles, s.guard, s.members.length, all.length);
    }

    /// @notice The owner-only administration every restricted Safe gets. See the contract documentation.
    function adminEntries(address safe, address roles, Setup calldata s)
        public
        pure
        returns (EngineEntry[] memory e)
    {
        bytes4[7] memory rolesAdmin = [
            ASSIGN_ROLES,
            SCOPE_TARGET,
            SCOPE_FUNCTION,
            ALLOW_FUNCTION,
            REVOKE_TARGET,
            REVOKE_FUNCTION,
            SET_ALLOWANCE
        ];
        e = new EngineEntry[](rolesAdmin.length + 2);
        for (uint256 i; i < rolesAdmin.length; i++) {
            e[i] = EngineEntry(roles, rolesAdmin[i], 0, s.ownerOnlyPolicy, "");
        }
        e[rolesAdmin.length] = EngineEntry(safe, DISABLE_MODULE, 0, s.ownerOnlyPolicy, "");
        e[rolesAdmin.length + 1] =
            EngineEntry(safe, SWAP_OWNER, 0, s.increasedThresholdPolicy, abi.encode(s.ownerSwapMaxAbsent));
    }

    /// @notice The Roles proxy address a Safe gets from `setUp`.
    function rolesAddress(address safe, address moduleProxyFactory, address rolesMastercopy)
        public
        pure
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(_rolesInitializer(safe)), ROLES_SALT_NONCE));
        bytes32 codeHash = keccak256(
            abi.encodePacked(
                hex"602d8060093d393df3363d3d373d3d3d363d73",
                rolesMastercopy,
                hex"5af43d82803e903d91602b57fd5bf3"
            )
        );
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), moduleProxyFactory, salt, codeHash))))
        );
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev `Safe.setup` sets the owners, then delegatecalls here: the nonce is still 0, no module is
    ///      enabled and no guard is set. An owner transaction always has nonce >= 1 at this point.
    function _requireSafeBeingSetUp() private view {
        (address[] memory modules,) = ISafeSetupTarget(address(this)).getModulesPaginated(SENTINEL_MODULES, 1);
        bytes32 guard;
        bytes32 moduleGuard;
        assembly ("memory-safe") {
            guard := sload(GUARD_SLOT)
            moduleGuard := sload(MODULE_GUARD_SLOT)
        }
        require(
            ISafeSetupTarget(address(this)).nonce() == 0 && modules.length == 0 && guard == 0
                && moduleGuard == 0,
            OnlyDuringSafeSetup()
        );
    }

    /// @dev Anyone can deploy the proxy first, with the same initializer: it is then owned by this Safe
    ///      already and nothing else can have happened to it, so it is reused.
    function _deployRoles(address safe, address factory, address mastercopy) private returns (address roles) {
        roles = rolesAddress(safe, factory, mastercopy);
        if (roles.code.length == 0) {
            address deployed = IModuleProxyFactory(factory)
                .deployModule(mastercopy, _rolesInitializer(safe), ROLES_SALT_NONCE);
            require(deployed == roles, RolesProxyMisconfigured(deployed));
        }
        require(
            IRolesSetup(roles).owner() == safe && IRolesSetup(roles).avatar() == safe
                && IRolesSetup(roles).target() == safe,
            RolesProxyMisconfigured(roles)
        );
    }

    function _rolesInitializer(address safe) private pure returns (bytes memory) {
        return abi.encodeWithSelector(ROLES_SETUP, abi.encode(safe, safe, safe));
    }

    /**
     * @dev Only the four permission-building calls, never naming the Safe, Roles or the guard, and never
     *      with ExecutionOptions other than None (no ETH value, no delegatecall).
     *        scopeTarget(bytes32 role, address target)
     *        allowFunction(bytes32 role, address target, bytes4, uint8 options)
     *        scopeFunction(bytes32 role, address target, bytes4, ConditionFlat[], uint8 options)
     *        setAllowance(bytes32 key, ...)
     */
    function _checkRolesCall(uint256 i, bytes calldata data, address safe, address roles, address guard)
        private
        pure
    {
        bytes4 selector = bytes4(data);
        if (selector == SET_ALLOWANCE) return;
        require(
            selector == SCOPE_TARGET || selector == ALLOW_FUNCTION || selector == SCOPE_FUNCTION,
            RolesCallNotAllowed(i, selector)
        );
        address target = address(uint160(uint256(_word(data, 1))));
        require(
            target != address(0) && target != safe && target != roles && target != guard,
            RolesCallTargetNotAllowed(i, target)
        );
        if (selector == SCOPE_TARGET) return;
        uint256 options = uint256(_word(data, selector == ALLOW_FUNCTION ? 3 : 4));
        require(options == 0, RolesCallOptionsNotAllowed(i, options));
    }

    /// @dev The `index`-th 32-byte head word of the arguments.
    function _word(bytes calldata data, uint256 index) private pure returns (bytes32) {
        return bytes32(data[4 + 32 * index:36 + 32 * index]);
    }

    function _requireCode(address account) private view {
        require(account.code.length > 0, NoCode(account));
    }

    function _bubble(bytes memory reason) private pure {
        assembly ("memory-safe") {
            revert(add(reason, 32), mload(reason))
        }
    }
}
