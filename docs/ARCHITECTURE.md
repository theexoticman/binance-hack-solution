# Architecture

## 1. Authority layers

| Layer | Holder | Can do | Enforced by |
|---|---|---|---|
| Root | Leadership M-of-N (Safe owners) | Everything: owners, threshold, modules, guard, fallback handler, sessions, policies, unrestricted transfers | `Safe.execTransaction` + `checkSignatures` |
| Operational | Session key (not an owner) | Exactly what its session's policies allow | ERC-4337 validation → Safe7579 → SmartSession → policies |

No other authority exists on the account. The setup test (`test_setup_authorityLayout`) asserts
this: the only Safe module is Safe7579, the only Safe7579 validator is SmartSession, and there are
no executors, no hooks and no guard.

## 2. Components

### Reused (pinned in `package.json`)

| Component | Version | Role here |
|---|---|---|
| Safe | `@safe-global/safe-contracts` 1.4.1 | Custody. Owners, threshold, module list. Leadership acts via `execTransaction`. |
| Safe7579 | v1.0.0 (via `@rhinestone/modulekit` 0.4.10) | Enabled as the Safe's **only module and fallback handler**. Implements ERC-4337 `validateUserOp` and ERC-7579 `execute`. Every mutating entrypoint is `onlyEntryPointOrSelf`. |
| EntryPoint | v0.7.0 at `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | Nonces (replay), userOp hash over chainId/EntryPoint/sender (domain separation), `validUntil` enforcement, reentrancy guard. Hard-coded in Safe7579. |
| SmartSession | `erc7579/smartsessions` @ `f5aaf86` | The **only ERC-7579 validator**. Owns session lifecycle (enable/remove), decodes executions, rejects unsupported modes, runs policies, then calls the session validator. |
| OwnableValidator | `rhinestonewtf/core-modules` @ `2eda90a` | Stateless session validator: 1-of-[sessionKey]. |
| TimeFramePolicy | SmartSessions external policy | User-op policy. Returns `validUntil`, which the EntryPoint enforces (`AA22`). |
| SimpleGasPolicy | SmartSessions external policy | User-op policy. Lifetime cap on gas units and on worst-case wei cost of user operations. Only a hard bound together with GasFeeCapPolicy. |

### Custom (this repo, the parts that need audit)

| Contract | Control |
|---|---|
| `SessionPolicyBase` | Shared base: storage namespacing `(configId, multiplexer, account)`, epoch-based reconfiguration, `PolicyNotInitialized` fail-closed. |
| `TransferLib` | Strict decoder. Classifies an execution as `NATIVE_TRANSFER` (empty calldata), `ERC20_TRANSFER` (exactly `transfer(address,uint256)`, 68 bytes, clean address, no value) or `UNSUPPORTED`. |
| `FunctionWhitelistPolicy` | **Which operations.** Native transfers on/off; `(target, selector)` allowlist; contract calls must carry value 0. Hard bans: the account itself, the multiplexer, and allowance selectors (`approve`, `increaseAllowance`, `setApprovalForAll`, `permit`). |
| `AddressWhitelistPolicy` | **To whom.** The *beneficiary*: `target` for native transfers, the decoded `to` for ERC-20 transfers. Anything else fails. |
| `SpendingLimitPolicy` | **How much.** Per-asset `maxPerTx` and `maxPerPeriod` over aligned windows (for example, UTC days). Unconfigured assets fail. |
| `GasFeeCapPolicy` | **How much gas.** User-op policy: `maxFeePerGas == maxPriorityFeePerGas ≤ cap`. In that fee mode SimpleGasPolicy's counted cost equals the EntryPoint prefund, which bounds the charge (SECURITY_REVIEW.md §2). |
| `ISessionPolicy` | MIT, ABI-identical declarations of the SmartSessions policy interfaces, so `src/` compiles no copyleft source. |

### Why not the existing policies?

- SmartSessions `ContractWhitelistPolicy` checks only the call **target**. For an ERC-20 transfer
  that is the token contract, so any beneficiary would pass.
- `UniActionPolicy`/`ArgPolicy` can constrain arguments, but cannot express "recipient ∈ list of
  N addresses" compactly, and are hard to review for this use.
- `ValueLimitPolicy` and `ERC20SpendingLimitPolicy` are lifetime caps. There is no per-period
  window and no per-transaction cap.
- `SudoPolicy` is the opposite of what we want. It appears in tests only as an attacker payload.

### Why not an executor module (e.g. ZyFAI GuardedExec)?

[GuardedExec](https://github.com/ondefy/zyfai-executor-module) is an ERC-7579 **executor**: the
session key calls the module, the module checks its registry and then calls
`executeFromExecutor`. This allows rich *post-execution* checks (e.g. health factor). The
trade-off is that the module, and whoever can upgrade it (UUPS) or edit its registry, holds
execution authority equivalent to root.

This template keeps the account free of executors, so the only non-owner path is the validation
path. Outcome assertions that need post-state belong in an execution-phase component (see
ADDING_POLICIES.md §6), added deliberately and audited as root-equivalent code.

## 3. A session operation, end to end

```
infra signs userOp
  sender     = Safe
  nonce      = EntryPoint.getNonce(Safe, key = SmartSession address << 32)
  callData   = Safe7579.execute(mode, executionCalldata)
  signature  = 0x00 (USE) ‖ permissionId ‖ ECDSA(userOpHash)

EntryPoint.handleOps
 └ Safe.fallback ─▶ Safe7579.validateUserOp            onlyEntryPoint; validator taken from nonce key
     └ Safe.execTransactionFromModuleReturnData ─▶ SmartSession.validateUserOp
         1. account == msg.sender == userOp.sender
         2. permissionId enabled for this account          else InvalidPermissionId
         3. paymaster used?  only if permitted             else PaymasterValidationNotEnabled
         4. user-op policies: TimeFramePolicy, SimpleGasPolicy, GasFeeCapPolicy
         5. callData selector:
              execute  → exec type must be DEFAULT          else UnsupportedExecutionType
                         call type SINGLE or BATCH          else UnsupportedCallType (delegatecall)
                         per execution: target == account && execute()  → InvalidSelfCall
                                        target == SmartSession → needs explicit grant → NoPoliciesSet
                                        else catch-all action: FunctionWhitelist, AddressWhitelist, SpendingLimit
              executeUserOp → UnsupportedExecutionType
              anything else (installModule, …) → needs explicit (account, selector) grant → NoPoliciesSet
         6. OwnableValidator.validateSignatureWithData(userOpHash, sig, [sessionKey])
     └ prefund paid by the Safe (bounded by SimpleGasPolicy)
 └ EntryPoint checks validUntil (AA22), nonce (AA25)
 └ Safe.fallback ─▶ Safe7579.execute ─▶ Safe.execTransactionFromModule(CALL)   (batch: via Safe7579 DCUtil)
```

Policies run in **validation**. A failing policy reverts the whole `validateUserOp`, so nothing
executes. Within a batch, every element is checked in order against shared state, so a batch
cannot split an over-limit transfer into pieces. The same holds for multiple ops in one bundle.

## 4. Session configuration

`SessionSetup.exchangeSession` produces:

```
Session {
  sessionValidator:          OwnableValidator
  sessionValidatorInitData:  abi.encode(1, [sessionKey])
  salt:                      distinguishes sessions with the same signer
  userOpPolicies:            [TimeFramePolicy(validUntil), SimpleGasPolicy(gasUnits, weiCap),
                              GasFeeCapPolicy(maxFeePerGas)]
  erc7739Policies:           none          → the session can never sign *as the Safe* (ERC-1271)
  actions:                   [ catch-all (FALLBACK_TARGET_FLAG, FALLBACK_TARGET_SELECTOR_FLAG):
                                 FunctionWhitelistPolicy(allowNative, [(USDC, transfer)])
                                 AddressWhitelistPolicy([alice, bob])
                                 SpendingLimitPolicy([(ETH, 1, 5/day), (USDC, 1000, 3000/day)]) ]
  permitERC4337Paymaster:    false
}
permissionId = keccak256(validator, validatorInitData, salt)
```

**Why a single catch-all action?** SmartSessions gives every `(target, selector)` action its own
`ConfigId`. If ETH and USDC transfers were separate actions, each would have a separate spending
counter, and "5 ETH per day per session" would become "5 ETH per day per action". Routing all
executions through one action gives one `ConfigId`, and therefore a true per-session aggregate.
The cost is that FunctionWhitelistPolicy, not SmartSessions' action routing, decides which
operations exist. You can add explicit actions as well (defence in depth), but then they need
their own spending configuration.

## 5. Storage and namespacing

Policies are called by SmartSession, but anyone can call them directly. All state is keyed:

```
mapping(ConfigId => mapping(address multiplexer => … => mapping(address account => …)))
```

- `multiplexer = msg.sender`. A direct caller only reads and writes its own namespace (see
  `test_B_reconfigurePolicyDirectly`, `test_A_routeOverwritePolicyNamespace`).
- `account` is the innermost key, as ERC-7562 associated-storage rules require.
- `epoch` increments on every `initializeWithMultiplexer`. Configuration (lists, limits) is keyed
  by epoch, so reconfiguration replaces it atomically. **Spending usage is not epoch-keyed**:
  raising a limit never refunds the current window.

## 6. Leadership operations

| Action | Safe transaction |
|---|---|
| Attach framework | DELEGATECALL `MultiSendCallOnly.multiSend(SessionSetup.attachSafe7579(...))` |
| Create session | CALL `SmartSession.enableSessions([session])` |
| Update a policy | CALL `SmartSession.enableActionPolicies(permissionId, [catch-all action with new PolicyData])` |
| Change expiry or gas budget | CALL `SmartSession.enableUserOpPolicies(permissionId, [...])` |
| Revoke | CALL `SmartSession.removeSession(permissionId)`. Never re-enable the same key with the same salt afterwards (SECURITY_REVIEW.md F4). |
| Any Safe admin | CALL to the Safe itself (e.g. `addOwnerWithThreshold`), or to the Safe7579 entrypoints via self-call |
| Emergency: kill all sessions | `Safe7579.uninstallModule(1, SmartSession, …)` via self-call, or `disableModule(Safe7579)` |
