# Threat Model and Adversarial Review

## 1. The guarantee

> Compromise of an operational session signer, including its private key and an EIP-7702
> delegation of its EOA to attacker code, does not compromise the Safe's root authority and does
> not grant access to funds beyond the session's explicitly authorised permissions.

This holds **only** under the assumptions in §2. It is a statement about this configuration (the
Safe has exactly one module, Safe7579; Safe7579 has exactly one validator, SmartSession; no
executors, hooks or guard). It is not a statement about any Safe.

## 2. Trusted components and assumptions

| # | Assumption | If violated |
|---|---|---|
| T1 | Leadership signers below the threshold are not colluding or compromised | Root compromise: everything is lost |
| T2 | Safe v1.4.1, Safe7579 v1.0.0, EntryPoint v0.7, SmartSession @ `f5aaf86`, OwnableValidator @ `2eda90a`, TimeFramePolicy and SimpleGasPolicy behave as specified | Depends on the bug; these are the audited, reused components |
| T3 | The four custom policies (incl. GasFeeCapPolicy) and `TransferLib` are correct | **Unaudited.** Their bugs are session-scope escapes |
| T4 | The Safe has **no other enabled module**, Safe7579 has **no executors and no other validators**, and no hook or fallback module adds execution paths | Any such module is an alternative path that bypasses session policies entirely |
| T5 | Whitelisted beneficiaries are destinations you are willing to lose the authorised budget to | Funds move onward from the beneficiary under its own rules |
| T6 | Whitelisted tokens behave like standard ERC-20 (`transfer(to, amount)` moves exactly `amount` to `to`) | A malicious or unusual token can move value differently than the decoded calldata says |
| T7 | Leadership configures sessions correctly (limits, whitelists, expiry, gas budget) | Misconfiguration is authorised, by definition |
| T8 | The chain implements EIP-7702 and the EntryPoint as specified | n/a |

**Not trusted:** session keys, any code at a session key's address, bundlers, `msg.sender`,
`tx.origin`, recipients' code, and any caller of the policy contracts.

## 3. What the design prevents, and what it does not

**Prevents** (all tested, see §4):

- Session-originated changes to owners, threshold, modules, guard, fallback handler, Safe7579
  module set or registry, or the Safe singleton.
- Session self-management: changing its own whitelist, limits, policies or expiry, creating or
  un-revoking sessions, or installing `SudoPolicy`.
- Transfers to non-whitelisted beneficiaries, above per-tx or per-period limits, of unconfigured
  assets, via approvals or `transferFrom`, or via intermediate contracts.
- `DELEGATECALL`, try-mode, `executeUserOp`, nested self-execution.
- Using the session to make the Safe sign messages (ERC-1271), or to use a paymaster.
- Gas-fee extraction beyond the session's gas budget.
- Replay across nonces, chains, and accounts; use after expiry or revocation.

**Does not prevent:**

- **Loss of the authorised budget.** A compromised session can send up to its remaining
  per-period limit, per asset, to whitelisted beneficiaries, every period until revoked. It can
  also spend its gas budget. *Size limits as a loss you accept, and monitor.*
- Anything done by a leadership quorum (T1).
- Compromise of an independent withdrawal-approval system that feeds the session key. If that
  system tells the session to pay a whitelisted address, the session pays.
- What happens after funds reach a beneficiary (T5).
- Griefing: a compromised key can burn its own budgets so that legitimate operations fail until
  the next period. That is a liveness issue, not a loss.

## 4. Adversarial review

Each row is a privilege-escalation path from the brief: the result and the test that checks it.

| Path | Analysis | Result | Tests |
|---|---|---|---|
| **Other Safe modules** | Any enabled Safe module can call `execTransactionFromModule` with no session checks. The design requires Safe7579 to be the only module (T4). Sessions cannot enable modules. | Holds only if T4 holds | `test_setup_authorityLayout`, `test_B_enableUnrestrictedSafeModule`, `test_A_routeSafeModuleExec_GS104` |
| **Safe7579 executors** | An installed 7579 executor gets `executeFromExecutor`, an unrestricted path that skips validation. None are installed. Sessions cannot install one: a self-call is blocked by FunctionWhitelist, and direct callData hits `NoPoliciesSet`. | Blocked | `test_B_install7579ExecutorViaSelfCall`, `test_B_install7579ExecutorDirectly`, `test_A_routeSafe7579Executor_notInstalled` |
| **Direct calls to the Safe** | Owner functions are `authorized` (Safe must call itself, `GS031`). `execTransaction` needs owner signatures (`GS026`). `execTransactionFromModule` needs an enabled module (`GS104`). | Blocked | `test_A_route*` |
| **Safe self-calls via the session** | `execute(Safe, adminCall)`: FunctionWhitelist bans `target == account` unconditionally, and its config rejects the account as a target. | Blocked | `test_B_addAttackerAsOwner`, `…reduceThreshold`, `…setGuard`, `…replaceFallbackHandler`, `test_C_nativeCallToAccountOrMultiplexer` |
| **DELEGATECALL** | SmartSession rejects call type `0xff` (`UnsupportedCallType`). FunctionWhitelist cannot express delegatecall. Safe7579 batch execution uses its own DCUtil, which only performs CALLs. | Blocked | `test_C_delegatecallMode`, `test_B_upgradeViaDelegatecallIsUnreachable` |
| **Nested execution** | `execute(Safe, execute(...))` reverts with `InvalidSelfCall` in SmartSession, also inside batches. `execute(Safe, execTransaction(...))` is blocked by the self-call ban. | Blocked | `test_C_nestedSelfExecute`, `test_C_batchContainingNestedExecute`, `test_B_innerExecTransaction` |
| **Batching** | SmartSession checks every batch element against the same policies and shared state. One bad element rejects the whole op. Aggregate limits accumulate within a batch and across a bundle. | Blocked | `test_C_batchSmugglingOneBadCall`, `test_C_aggregateLimitWithinOneBatch`, `test_C_aggregateLimitWithinOneBundle`, `test_C_emptyBatch` |
| **ERC-7579 module management** | `installModule`, `uninstallModule`, `setRegistry` and `initializeAccount` on Safe7579 are `onlyEntryPointOrSelf`. Through the EntryPoint they need a SmartSession action for `(account, selector)`, which never exists. | Blocked | `test_B_install7579HookDirectly`, `test_B_uninstallSmartSessionValidator`, `test_B_changeAdapterRegistry`, `test_A_routeInstall7579Executor_unauthorized` |
| **Fallback handler** | Safe7579 *is* the fallback handler. It authenticates the original caller with ERC-2771 `_msgSender()`, and unknown selectors revert (no 7579 fallback modules installed). Replacing the handler is a Safe self-call (blocked). | Blocked | `test_B_replaceFallbackHandler`, `test_A_routeSafe7579Execute_unauthorized` |
| **ERC-1271 (Safe signing)** | Sessions have no ERC-7739 content and no 1271 policy, so SmartSession's `isValidSignatureWithSender` returns false. Signatures routed to "no validator" fall back to the owners' `checkSignatures`. This matters because Permit2 and off-chain orders pull funds on a valid 1271 signature. | Blocked | `test_B_sessionCannotProduceSafeErc1271Signature` |
| **ERC-1271 (session signer)** | See §5. The session validator accepts contract signatures. | Finding, bounded by policies | `test_A_erc1271SignerHijack_…` |
| **"Enable mode"** | SmartSessions can enable a session inside a userOp, if the *account* signed it. The session key can only offer its own signature: it hits `Safe.checkSignatures` (`GS020`), and SmartSession refuses to authorise its own enable flow (`InvalidEnableSignature`). | Blocked | `test_B_enableModeWithForgedSafeSignature`, `test_B_enableModeViaSessionErc1271` |
| **Allowances / indirect transfers** | Allowance selectors cannot be whitelisted. `transferFrom` is not whitelisted. AddressWhitelist only accepts plain transfers, so routers and forwarders fail even if mistakenly whitelisted. | Blocked | `test_C_erc20Approve`, `test_C_erc20TransferFrom`, `test_C_intermediateContractCannotLaunderBeneficiary`, `test_C_config_functionPolicyRejectsDangerousEntries` |
| **Calldata tricks** | TransferLib requires exactly 68 bytes, clean address padding, and value 0 for ERC-20. 1–3 byte calldata is rejected. | Blocked | `test_C_transferWithTrailingCalldata`, `…DirtyAddressBits`, `…CarryingEth`, `…ShortCalldataHittingFallback` |
| **Reentrancy** | Policies run before execution and make no state-changing external calls. A recipient re-entering `handleOps` hits the EntryPoint's guard. A recipient calling the Safe has no authority. | Blocked | `test_C_reentrancyFromRecipientIsRejected` |
| **Replay / domain separation** | The EntryPoint 2D nonce (key = SmartSession) prevents replay. The userOp hash commits to chainId, EntryPoint and sender. The permissionId namespace is per account. | Blocked | `test_C_replayConsumedOperation`, `test_C_crossChainReplay`, `test_C_crossAccountReplay` |
| **Expiry / revocation** | TimeFramePolicy → `validUntil` → `AA22`. `removeSession` → `InvalidPermissionId`, including for already-signed ops of every signature type. **Exception:** re-enabling the same key with the same salt revives unused pre-signed ops (§5). | Blocked | `test_C_expiredSession`, `test_C_revokedSession`, `Revocation.t.sol` |
| **Gas fees** | **Finding.** The Safe pays ERC-4337 gas. A compromised key can sign a harmless op with an absurd fee and a large `preVerificationGas`, bundle it itself, and collect the fee as beneficiary. Without a gas policy this extracted **42 ETH in one op**, more than 8× the daily spending limit. `SimpleGasPolicy` alone still leaves prefund parking and an EIP-1559 under-count. `GasFeeCapPolicy` closes both, so gas outflow ≤ `gasCostLimit` (SECURITY_REVIEW.md §2). | Bounded by the gas budget | `GasAccounting.t.sol`, `test_C_gasFeeExtraction_*` |
| **Paymasters** | `permitERC4337Paymaster = false` → `PaymasterValidationNotEnabled`. | Blocked | `test_C_paymasterNotPermitted` |
| **Policy tampering** | Policies are public. State is namespaced by `msg.sender`, so direct calls only touch the caller's namespace. Calls *through* the Safe to a policy are blocked by FunctionWhitelist. | Blocked | `test_B_reconfigurePolicyDirectly`, `test_B_reconfigurePolicyThroughSafe`, `test_A_routeOverwritePolicyNamespace` |
| **Proxy upgrades** | Safe 1.4.1 has no upgrade function. Changing `singleton` requires a DELEGATECALL from the Safe (unreachable for sessions). Safe7579, SmartSession and the policies are not upgradeable proxies here. | Blocked | `test_B_upgradeViaDelegatecallIsUnreachable`, singleton slot in `_assertUnchanged` |
| **`msg.sender` / `tx.origin`** | Neither SmartSession nor the policies read them for authorisation. Authority comes only from the signature over the userOp hash. | Not applicable | `test_A_delegatedEoaAsBundler` |

## 5. EIP-7702

**What 7702 gives the attacker.** The key holder can set *their own EOA's* code
(`0xef0100 ‖ implementation`) with a signed authorization. It cannot change the Safe's code,
owners or modules, or any other account (`test_A_delegationChangesOnlyTheSessionEoa`).

**What the delegated code can try**, all executed as the session EOA
(`src/examples/MaliciousDelegation.sol`): pose as a module (`GS104`), as owners (`GS026`), call
Safe7579 `execute` (`AccountAccessUnauthorized`) or `executeFromExecutor` (`InvalidModule`), pull
tokens (`ERC20InsufficientAllowance`), add an owner or module (`GS031`), install an executor,
call SmartSession directly (`InvalidUserOpSender`), overwrite policy state (namespaced), and act
as the bundler. All of these fail, in tests and in the anvil demo, where the delegation is a real
type-4 transaction.

**Finding: the session validator assumes the signer has no code.** OwnableValidator uses
CheckNSignatures, which accepts Safe-style contract signatures (`v = 0`, signer address in `r`)
verified with `signer.isValidSignature(hash, data)`. A plain EOA has no code, so that path cannot
verify. After a 7702 delegation the session EOA has attacker-defined `isValidSignature`, so
**anyone, with no key, can produce valid session signatures**. Consequences:

- No new authority: every operation is still bound by the session's policies
  (`test_A_erc1271SignerHijack_anyoneCanDriveSession_withinPolicyOnly`).
- The attacker can discard or rotate the stolen key and still use the session. Key rotation
  without `removeSession` is not a fix: **revoke the session**.
- It cannot be used against *another* session: that session's signer list does not contain the
  hijacked EOA, and signers without code cannot verify (`test_A_cannotSwitchToAnotherSessionsPermissions`).

*Exact code path* (pinned sources): `OwnableValidator.validateSignatureWithData` (L316) →
`CheckSignatures.recoverNSignatures` (L339) → the `v == 0` branch calls
`ISignatureValidator(r).isValidSignature` (CheckNSignatures.sol L49–L91); the signer must be in the
session's owner list (OwnableValidator L349).

**Revocation.** `removeSession` is a Safe transaction the session cannot reach or block. Every
pre-signed operation, ECDSA or hijacked, then fails with `InvalidPermissionId`, and stays dead
while other sessions advance the shared nonce sequence (`Revocation.t.sol`). Two rules follow:

- **Never re-enable a revoked key with the same salt.** `permissionId = keccak256(validator,
  validatorInitData, salt)` does not include the policies. Re-enabling the same key and salt
  recreates the permissionId and revives unused pre-signed ops
  (`test_R_hazard_reEnableSameKeySameSaltRevivesPresignedOps`). Use a new key; a new salt also works.
- **Burning EntryPoint nonces is not revocation** (`test_R_nonceBurnIsNotRevocation`).

*Recommendation:* for EOA session keys, consider a session validator that only does ECDSA
recovery (e.g. SmartSessions' test `SimpleSessionValidator` pattern) so that delegated code
cannot produce signatures. We kept OwnableValidator because it is the audited, deployed
component. The issue is documented and tested rather than hidden by swapping validators.

**The same issue applies to leadership owners.** The Safe is a contract and cannot be
7702-delegated, but its owners are EOAs. Safe v1.4.1 `checkSignatures` also accepts contract
signatures (`v = 0`) and verifies them with the owner's `isValidSignature` (`GS024`). If an
owner's EOA is delegated to code whose ERC-1271 logic is weaker than "signed by my key" (a buggy
or permissive smart-wallet implementation), that owner's approval can be produced without their
key. **Operational rule: leadership EOAs must not 7702-delegate, or only to implementations
audited for this.** Monitor owner addresses for delegation designators.

## 6. Stateful accounting

- **When usage is recorded:** during ERC-4337 validation, when the operation is authorised.
  Validation and execution are atomic for policy purposes. If any policy fails, validation
  reverts and nothing is recorded or executed.
- **Failed executions:** if validation passes but the *execution* reverts (e.g. the recipient
  reverts), the EntryPoint keeps the validation state, so the budget stays consumed. The policy
  over-counts and never under-counts. `SpendingLimitPolicy` rejects transfers the Safe cannot
  cover, to make this rare (`test_C_insufficientBalanceIsRejectedNotCounted`,
  `test_C_failedExecutionConsumesBudget_failSafe`). Exact successful-only accounting would need an
  execution-phase component (ADDING_POLICIES.md §6).
- **Windows:** fixed, aligned windows (`block.timestamp - block.timestamp % period`). Up to 2×
  `maxPerPeriod` can move across a window boundary. Use a smaller period or a rolling design if
  that matters.
- **Reconfiguration:** `SpendingLimitPolicy` keeps usage across re-initialisation, so a raised
  limit never refunds (`test_D_leadershipRaisesLimit_neverRefundsSpentBudget`). The reused
  `SimpleGasPolicy` **resets** its usage on re-initialisation, so re-configuring the gas budget
  refills it.
- **Gas:** a separate, lifetime ETH budget per session. With GasFeeCapPolicy the counted cost
  equals the EntryPoint prefund, which bounds what is charged, so the Safe's gas outflow is
  ≤ `gasCostLimit` (SECURITY_REVIEW.md §2). Count it in the ETH risk budget:
  worst case = `maxPerPeriod × windows until revocation + gasCostLimit`.
- **Across sessions:** counters are per `ConfigId` (account, permissionId, action), so one
  session's failed operations never consume another's budget. The one shared resource is the
  Safe's balance inside a single bundle (`test_I_sameBundleBalanceContentionOverCountsOtherSession`).
  Submit each session's ops in its own `handleOps` call.
- **Successful-only accounting** was investigated and not adopted. Hooks see no session identity,
  SmartSessions rejects `executeUserOp`, and every design needs new root-equivalent code whose
  failure mode is under-counting (SECURITY_REVIEW.md §5).

## 7. ERC-4337 mempool constraints (ERC-7562)

Tested, not assumed (`test/Erc7562Compliance.t.sol`, run with `-vvv`; method and results in
SECURITY_REVIEW.md §4). In the default session, the **only** ERC-7562 violations are in
`SpendingLimitPolicy`:

- `TIMESTAMP` (OP-011), always;
- `BALANCE` (OP-080, unstaked), for native transfers only.

The rest of the stack is compliant with the opcode and storage rules, and the upstream simulator
accepts it: Safe, Safe7579, SmartSession, OwnableValidator, TimeFramePolicy, SimpleGasPolicy (with
GasFeeCapPolicy) and both whitelists. `SimpleGasPolicy` reads `BASEFEE` only in split-fee mode,
which GasFeeCapPolicy rejects.

Sessions that include SpendingLimitPolicy therefore need the operator's own bundler, or a bundler
that relaxes these rules. Bundlers differ, so verify on the target network. **This is a liveness
and compatibility constraint only: the on-chain checks do not depend on who bundles**
(`test_A_delegatedEoaAsBundler` uses the attacker as bundler).

## 8. Before mainnet

- Independent audit of `SessionPolicyBase`, the four policies, `TransferLib`, `SessionSetup`, and
  your exact deployment and configuration transactions.
- Confirm that the upstream audit reports (shipped in the SmartSessions, Safe7579 and core-modules
  repositories) cover the **exact pinned commits**, or move to commits they cover.
- Decide on OwnableValidator vs an ECDSA-only session validator (§5).
- Check every token you whitelist against T6 (fee-on-transfer, rebasing, blocklists, hooks,
  upgradeable tokens, tokens with a second `transfer` entrypoint).
- Monitoring: alert on `SpendRecorded`, `SessionCreated`/`SessionRemoved`, `PolicySet`,
  Safe `ChangedThreshold`/`AddedOwner`/`EnabledModule`/`ChangedGuard`/`ChangedFallbackHandler`,
  and on any 7702 delegation of a session-key address.
- Incident runbook: leadership `removeSession` (one session), or uninstall SmartSession or disable
  Safe7579 (all sessions). Pre-sign and rehearse it.
- Operate your own bundler and fund the EntryPoint deposit deliberately. Size the gas budget for
  real fees.
- Revocation runbook rule: never re-enable a revoked key with the same salt (§5).
- Licences: SmartSession and OwnableValidator compile AGPL-3.0-only sources. Upstream repositories
  ship no LICENSE file and contain `UNLICENSED` / untagged files. See SECURITY_REVIEW.md §7.
