// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ConditionFlat, ParameterType, Operator, ExecutionOptions } from "zodiac-roles/Types.sol";

/// @dev ABI of `SafePolicyGuard.Configuration` (safe-research/policy-engine).
struct EngineEntry {
    address target;
    bytes4 selector;
    uint8 operation; // 0 CALL, 1 DELEGATECALL
    address policy;
    bytes data;
}

/// @dev One owner transaction (always a CALL from the Safe).
struct OwnerCall {
    address to;
    bytes data;
}

/**
 * @notice What the Safe owners sign to run a Safenet sentinel from a Safe (safe-research/safenet @ c355af1).
 *
 *   The Safe is the registered sentinel (`SentinelOracle.addSentinel(safe)`). It holds the fee token,
 *   posts bonds, and receives bond returns and fee rewards: the oracle uses `msg.sender` for all
 *   three, so commit, reveal and claim must all come from the Safe.
 *
 *   The sentinel server holds one key with the Zodiac Roles role SENTINEL. It can make the Safe send
 *   the six transactions the sentinel service builds (`SentinelEncoder::encode_action_kind`):
 *
 *     feeToken.approve(oracle, bond)     spender = that market's oracle, amount <= maxBond
 *     oracle.commit / reveal / finalize / claim / timeoutArbitration
 *
 *   A market is one (fee token, oracle) pair. `SentinelOracle.FEE_TOKEN` is immutable, so a new fee
 *   token always comes with a new oracle deployment: adding one is adding a market.
 *
 *   Two layers enforce the same mandate:
 *     Roles (the key's mandate):      only those calls, no ETH value, no delegatecall, no batches
 *     Safe Policy Engine (the floor): default-deny for the key, for the Roles module AND for the
 *                                     owners; the approve spender and cap are enforced here too
 */
library SentinelSetup {
    bytes32 internal constant ROLE = keccak256("SENTINEL");

    bytes4 internal constant APPROVE = bytes4(keccak256("approve(address,uint256)"));
    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 internal constant COMMIT = bytes4(keccak256("commit(bytes32,bytes32)"));
    bytes4 internal constant REVEAL = bytes4(keccak256("reveal(bytes32,bool,bytes32,string)"));
    bytes4 internal constant FINALIZE = bytes4(keccak256("finalize(bytes32)"));
    bytes4 internal constant CLAIM = bytes4(keccak256("claim(bytes32)"));
    bytes4 internal constant TIMEOUT_ARBITRATION = bytes4(keccak256("timeoutArbitration(bytes32)"));

    // Admin calls, reachable by the owners only (OwnerOnlyPolicy)
    bytes4 internal constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));
    bytes4 internal constant DISABLE_MODULE = bytes4(keccak256("disableModule(address,address)"));
    bytes4 internal constant ASSIGN_ROLES = bytes4(keccak256("assignRoles(address,bytes32[],bool[])"));
    bytes4 internal constant SCOPE_TARGET = bytes4(keccak256("scopeTarget(bytes32,address)"));
    bytes4 internal constant SCOPE_FUNCTION =
        bytes4(keccak256("scopeFunction(bytes32,address,bytes4,(uint8,uint8,uint8,bytes)[],uint8)"));
    bytes4 internal constant ALLOW_FUNCTION =
        bytes4(keccak256("allowFunction(bytes32,address,bytes4,uint8)"));
    bytes4 internal constant REVOKE_TARGET = bytes4(keccak256("revokeTarget(bytes32,address)"));

    function oracleSelectors() internal pure returns (bytes4[5] memory) {
        return [COMMIT, REVEAL, FINALIZE, CLAIM, TIMEOUT_ARBITRATION];
    }

    struct Market {
        address feeToken; // USDC.e today
        address oracle; // the SentinelOracle whose FEE_TOKEN is `feeToken`
        uint256 maxBond; // 800e6 for USDC.e
    }

    struct Policies {
        address approveCap; // ERC20ApproveCapPolicy (this repository)
        address allow; // AllowPolicy
        address erc20Transfer; // ERC20TransferPolicy
        address increasedThreshold; // IncreasedThresholdPolicy
        address ownerOnly; // OwnerOnlyPolicy (this repository)
    }

    /*//////////////////////////////////////////////////////////////
                           ZODIAC ROLES (layer 1)
    //////////////////////////////////////////////////////////////*/

    /// Roles scope for `feeToken.approve(spender, amount)`: spender == oracle, amount <= maxBond.
    function approveScope(address oracle, uint256 maxBond) internal pure returns (ConditionFlat[] memory c) {
        c = new ConditionFlat[](3);
        c[0] = ConditionFlat(0, ParameterType.Calldata, Operator.Matches, "");
        c[1] = ConditionFlat(0, ParameterType.Static, Operator.EqualTo, abi.encode(oracle));
        c[2] = ConditionFlat(0, ParameterType.Static, Operator.LessThan, abi.encode(maxBond + 1));
    }

    /// The Roles calls that give the SENTINEL role one market. Each is one owner transaction.
    function rolesAddMarket(address roles, Market memory m) internal pure returns (OwnerCall[] memory calls) {
        bytes4[5] memory sels = oracleSelectors();
        calls = new OwnerCall[](3 + sels.length);
        calls[0] = OwnerCall(roles, abi.encodeWithSelector(SCOPE_TARGET, ROLE, m.feeToken));
        calls[1] = OwnerCall(
            roles,
            abi.encodeWithSelector(
                SCOPE_FUNCTION,
                ROLE,
                m.feeToken,
                APPROVE,
                approveScope(m.oracle, m.maxBond),
                uint8(ExecutionOptions.None)
            )
        );
        calls[2] = OwnerCall(roles, abi.encodeWithSelector(SCOPE_TARGET, ROLE, m.oracle));
        for (uint256 i; i < sels.length; i++) {
            calls[3 + i] = OwnerCall(
                roles,
                abi.encodeWithSelector(ALLOW_FUNCTION, ROLE, m.oracle, sels[i], uint8(ExecutionOptions.None))
            );
        }
    }

    /// Removing a market from the role: two owner transactions, effective immediately.
    function rolesRemoveMarket(address roles, Market memory m)
        internal
        pure
        returns (OwnerCall[] memory calls)
    {
        calls = new OwnerCall[](2);
        calls[0] = OwnerCall(roles, abi.encodeWithSelector(REVOKE_TARGET, ROLE, m.feeToken));
        calls[1] = OwnerCall(roles, abi.encodeWithSelector(REVOKE_TARGET, ROLE, m.oracle));
    }

    /// Grant (`member`) or revoke (`!member`) the SENTINEL role. One owner transaction each.
    function rolesAssign(address roles, address key, bool member) internal pure returns (OwnerCall memory) {
        bytes32[] memory r = new bytes32[](1);
        r[0] = ROLE;
        bool[] memory b = new bool[](1);
        b[0] = member;
        return OwnerCall(roles, abi.encodeWithSelector(ASSIGN_ROLES, key, r, b));
    }

    /// Owner transaction: enable Roles as the Safe's module.
    function enableRoles(address safe, address roles) internal pure returns (OwnerCall memory) {
        return OwnerCall(safe, abi.encodeWithSignature("enableModule(address)", roles));
    }

    /*//////////////////////////////////////////////////////////////
                       SAFE POLICY ENGINE (layer 2)
    //////////////////////////////////////////////////////////////*/

    /**
     * Entries for one market:
     *   feeToken.approve        ERC20ApproveCapPolicy   spender = oracle, amount <= maxBond
     *   oracle.commit / reveal / finalize / claim / timeoutArbitration   AllowPolicy
     *   feeToken.transfer       ERC20TransferPolicy     recipient = treasury (owners withdraw)
     */
    function marketEntries(Market memory m, address treasury, Policies memory p)
        internal
        pure
        returns (EngineEntry[] memory e)
    {
        bytes4[5] memory sels = oracleSelectors();
        e = new EngineEntry[](2 + sels.length);
        e[0] = EngineEntry(m.feeToken, APPROVE, 0, p.approveCap, _approveCapData(m.oracle, m.maxBond));
        for (uint256 i; i < sels.length; i++) {
            e[1 + i] = EngineEntry(m.oracle, sels[i], 0, p.allow, "");
        }
        e[1 + sels.length] = EngineEntry(m.feeToken, TRANSFER, 0, p.erc20Transfer, _recipientData(treasury));
    }

    /**
     * Admin entries (owner transactions only; a module, Roles included, can never reach them):
     *   Roles.assignRoles                   key rotation and revocation
     *   Roles.scopeTarget / scopeFunction /
     *     allowFunction / revokeTarget      add or remove a market on the role
     *   Safe.disableModule                  kill switch: detach Roles entirely
     *   Safe.swapOwner                      IncreasedThresholdPolicy: owner replacement needs 4 of 5
     *
     * Without these, default-deny would also lock the owners out of rotating the key once the guard
     * is installed. MultiSend has no entry, so batches are denied for the owners as well.
     */
    function adminEntries(address safe, address roles, Policies memory p)
        internal
        pure
        returns (EngineEntry[] memory e)
    {
        bytes4[5] memory rolesAdmin =
            [ASSIGN_ROLES, SCOPE_TARGET, SCOPE_FUNCTION, ALLOW_FUNCTION, REVOKE_TARGET];
        e = new EngineEntry[](rolesAdmin.length + 2);
        for (uint256 i; i < rolesAdmin.length; i++) {
            e[i] = EngineEntry(roles, rolesAdmin[i], 0, p.ownerOnly, "");
        }
        e[rolesAdmin.length] = EngineEntry(safe, DISABLE_MODULE, 0, p.ownerOnly, "");
        e[rolesAdmin.length + 1] =
            EngineEntry(safe, SWAP_OWNER, 0, p.increasedThreshold, abi.encode(uint256(1)));
    }

    function allEntries(
        address safe,
        address roles,
        address treasury,
        Market[] memory markets,
        Policies memory p
    ) internal pure returns (EngineEntry[] memory all) {
        all = adminEntries(safe, roles, p);
        for (uint256 i; i < markets.length; i++) {
            all = concat(all, marketEntries(markets[i], treasury, p));
        }
    }

    /// Owner tx, only before the guard exists: `guard.configureImmediately(entries)`.
    function configureImmediately(EngineEntry[] memory entries) internal pure returns (bytes memory) {
        return
            abi.encodeWithSignature("configureImmediately((address,bytes4,uint8,address,bytes)[])", entries);
    }

    /// After the guard exists, entries change in two owner txs separated by the engine delay:
    /// `requestConfiguration(root)`, then `applyConfiguration(entries)`.
    function configurationRoot(EngineEntry[] memory entries) internal pure returns (bytes32) {
        return keccak256(abi.encode(entries));
    }

    function requestConfiguration(EngineEntry[] memory entries) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("requestConfiguration(bytes32)", configurationRoot(entries));
    }

    function applyConfiguration(EngineEntry[] memory entries) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("applyConfiguration((address,bytes4,uint8,address,bytes)[])", entries);
    }

    /// Owner calls, only before the guard exists: install the guard as transaction AND module guard.
    /// The module guard must go first: once the transaction guard is set, default-deny blocks `setModuleGuard`.
    function installGuards(address safe, address guard) internal pure returns (OwnerCall[] memory calls) {
        calls = new OwnerCall[](2);
        calls[0] = OwnerCall(safe, abi.encodeWithSignature("setModuleGuard(address)", guard));
        calls[1] = OwnerCall(safe, abi.encodeWithSignature("setGuard(address)", guard));
    }

    /*//////////////////////////////////////////////////////////////
                          WHAT THE SERVER SENDS
    //////////////////////////////////////////////////////////////*/

    /**
     * The server's transaction for one sentinel action: from its key to the Roles module, value 0.
     * `shouldRevert = true` makes a denied or failed call revert the transaction, like the raw call.
     */
    function wrap(address to, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeWithSignature(
            "execTransactionWithRole(address,uint256,bytes,uint8,bytes32,bool)", to, 0, data, 0, ROLE, true
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev `ERC20ApproveCapPolicy.SpenderCap[]` with one entry.
    function _approveCapData(address spender, uint256 maxBond) private pure returns (bytes memory) {
        Cap[] memory c = new Cap[](1);
        c[0] = Cap(spender, true, uint248(maxBond));
        return abi.encode(c);
    }

    struct Cap {
        address spender;
        bool allowed;
        uint248 maxAmount;
    }

    /// @dev Upstream `ERC20TransferPolicy.RecipientData[]` with one ALWAYS entry.
    function _recipientData(address recipient) private pure returns (bytes memory) {
        Recipient[] memory r = new Recipient[](1);
        r[0] = Recipient(recipient, 2);
        return abi.encode(r);
    }

    struct Recipient {
        address recipient;
        uint8 permission;
    }

    /**
     * MultiSendCallOnly payload for the ONE-TIME bootstrap, sent before the guard exists (DELEGATECALL
     * MultiSendCallOnly). The engine has no MultiSend entry, so once the guard is installed batches are
     * denied to everyone; every later change is a single owner transaction.
     */
    function toMultiSend(OwnerCall[] memory calls) internal pure returns (bytes memory txs) {
        for (uint256 i; i < calls.length; i++) {
            txs =
                abi.encodePacked(txs, uint8(0), calls[i].to, uint256(0), calls[i].data.length, calls[i].data);
        }
    }

    function concat(OwnerCall[] memory a, OwnerCall[] memory b) internal pure returns (OwnerCall[] memory c) {
        c = new OwnerCall[](a.length + b.length);
        for (uint256 i; i < a.length; i++) {
            c[i] = a[i];
        }
        for (uint256 i; i < b.length; i++) {
            c[a.length + i] = b[i];
        }
    }

    function concat(EngineEntry[] memory a, EngineEntry[] memory b)
        internal
        pure
        returns (EngineEntry[] memory c)
    {
        c = new EngineEntry[](a.length + b.length);
        for (uint256 i; i < a.length; i++) {
            c[i] = a[i];
        }
        for (uint256 i; i < b.length; i++) {
            c[a.length + i] = b[i];
        }
    }
}
