# Security Review (pre-publication)

Internal adversarial review of this repository before publishing it as an **unaudited reference
implementation**. It is not a substitute for an independent audit.

- **Pinned stack:** Safe 1.4.1 · Safe7579 1.0.0 · EntryPoint v0.7.0 · SmartSessions `f5aaf86` ·
  core-modules `2eda90a` (OwnableValidator) · solc 0.8.30 · EVM prague.
- **Reproduce:** `pnpm install && pnpm test`. That runs `forge test` (122 tests, plus 7 that report
  as skipped without a tracer) and `forge test --mc Erc7562ComplianceTest -vvv` (the 7
  trace-based tests). Then `./script/demo.sh` and `./script/check-licenses.sh`.

## 1. Findings

| # | Finding | Severity | Status | Evidence |
|---|---|---|---|---|
| F1 | A compromised key can make the Safe pay arbitrary gas fees to an attacker-run bundler, bypassing every spending limit. Measured: **42.47 ETH in one op** (8.5× the daily ETH limit). | Critical | **Fixed**: SimpleGasPolicy (reused) caps the session's gas cost | `PolicyEnforcement.t.sol::test_C_gasFeeExtraction_withoutGasPolicy_bypassesSpendingLimits`, `…_blockedBySimpleGasPolicy` |
| F2 | SimpleGasPolicy alone does not bound what the EntryPoint takes. (a) **Prefund parking**: with priority fee 0 it counts 0 while the Safe sends `limits × maxFeePerGas` to the EntryPoint (42.5 ETH of liquidity locked in one op). (b) **Under-count** in EIP-1559 mode: 213,237 gas charged vs 210,000 counted. | High | **Fixed**: new `GasFeeCapPolicy` requires `maxFeePerGas == maxPriorityFeePerGas` and caps it | `GasAccounting.t.sol::test_gas_gap_*` (gap reproduced), `test_gas_fix_*`, `testFuzz_gas_totalOutflowBoundedByBudget` |
| F3 | After an EIP-7702 delegation of the session EOA, its code can approve operations **for that session** without the key (OwnableValidator accepts `v = 0` contract signatures). No new authority, and no other session is affected. | Medium | Documented; remedy is revocation | `Malicious7702Delegation.t.sol::test_A_erc1271SignerHijack_…`, `test_A_cannotSwitchToAnotherSessionsPermissions`; code refs in §3 |
| F4 | Re-enabling a revoked session with the **same key and salt** recreates the same permissionId and revives unused pre-signed operations. | Medium | Documented operational rule: never re-enable a revoked key; rotate keys or change the salt | `Revocation.t.sol::test_R_hazard_reEnableSameKeySameSaltRevivesPresignedOps`, `test_R_reEnableWithNewSaltOrNewKeyDoesNotRevive` |
| F5 | Two sessions' ops in **one bundle** contend for the Safe's balance. The second can be validated, charged, and then revert. Over-count only; nothing moves. | Low | Documented; mitigation: one session per `handleOps` | `AccountingIsolation.t.sol::test_I_sameBundleBalanceContentionOverCountsOtherSession`, `test_I_separateBundlesRemoveContention` |
| F6 | The earlier statement "public bundlers will reject the operations" was imprecise. Exactly one contract is non-compliant with ERC-7562: SpendingLimitPolicy, via `TIMESTAMP` (OP-011) and `BALANCE` (OP-080, native transfers only). | Info | **Corrected** in docs and **tested** | `Erc7562Compliance.t.sol` (§4) |
| F7 | `src/` policies compiled AGPL-3.0-only, GPL-3.0 and LGPL-3.0 sources through interface imports. Upstream licensing is ambiguous (§7). | Info (legal) | **Fixed** for `src/`: MIT-only, ABI-identical interfaces. Upstream: open | `script/check-licenses.sh`, `LicenseIsolation.t.sol` |

## 2. Gas accounting (item 1)

**Claim.** With SimpleGasPolicy and GasFeeCapPolicy on a session, the ETH that leaves the Safe for
gas, to any bundler or into its EntryPoint deposit, over the life of that session's gas
configuration is **≤ `gasCostLimit`**. This holds for any number of operations, any gas limits, any
fee within the cap, any basefee, and any bundler.

**Why**, from the code:

1. `GasFeeCapPolicy.checkUserOpPolicy` rejects `maxFeePerGas != maxPriorityFeePerGas` and fees
   above the cap.
2. With equal fees, `UserOperationLib.gasPrice` and `EntryPoint.getUserOpGasPrice` both return
   `maxFeePerGas` (legacy branch; no `BASEFEE` read). So `SimpleGasPolicy.checkUserOpPolicy` counts
   `(verificationGasLimit + callGasLimit + preVerificationGas) × maxFeePerGas`, which is exactly
   `EntryPoint._getRequiredPrefund` (paymasters are disabled for the session).
3. `EntryPoint._postExecution` never charges more than the prefund. Above it, the inner call
   reverts with `INNER_REVERT_LOW_PREFUND` and `actualGasCost = prefund`. The remainder is refunded
   to the Safe's deposit.
4. `Safe7579.validateUserOp` sends at most `missingAccountFunds ≤ prefund`. A rejected op reverts
   the whole `handleOps`, so nothing is paid.

**Tests.**

- `test_gas_fix_countedEqualsPrefundAndBoundsCharge`: counted == prefund ≥ charge, for one op.
- `testFuzz_gas_totalOutflowBoundedByBudget` (256 runs by default; also run with 2,001): 12 ops per
  run with random verification/call/pre-verification gas, fees from 0 to 2× the cap, a quarter of
  them with split fees, random basefee, attacker as beneficiary. It asserts that outflow ≤ budget,
  outflow == bundler receipts + deposit, and bundler receipts ≤ counted.
- `test_gas_budgetExhaustionStopsPaidOperations`: the budget runs out and further ops are rejected.

**Limits of the claim.**

- The budget is **per session**: N compromised sessions can lose the sum of N budgets
  (`test_gas_budgetsArePerSession`).
- It is a **lifetime** budget that **resets** whenever leadership re-initialises SimpleGasPolicy,
  including on re-enabling a removed session (`test_gas_reinitialisationResetsBudget_leadershipOnly`).
- ETH parked in the EntryPoint deposit is still Safe property, recoverable only by leadership
  (`test_gas_sessionCannotWithdrawEntryPointDeposit`).

**Is gas part of the withdrawal budget? Yes, for risk sizing.** It is a separate on-chain counter
in the same asset. The worst-case ETH loss of one compromised session, revoked after it touched
`k` spending windows, is:

`ETH maxPerPeriod × k + gasCostLimit`, to whitelisted beneficiaries and to bundlers respectively.

The two counters are not merged on-chain: gas is lifetime-scoped and worst-case-priced, spending
is per-window. Merging them would couple two policies' state. Set `gasCostLimit` deliberately
small and count it in the ETH risk budget.

## 3. EIP-7702 and signature validation (item 2)

**From the implementation.** `SignerLib.isValidISessionValidator` → `OwnableValidator.validateSignatureWithData`
(`OwnableValidator.sol` L316) → `CheckSignatures.recoverNSignatures` (L339):

- `v == 0` → signer = `r`, accepted if `ISignatureValidator(signer).isValidSignature(hash, data)`
  returns the magic value (`CheckNSignatures.sol` L49–L91);
- `v > 30` → ECDSA over the eth_sign hash (L92–L101); otherwise plain ECDSA (L103);
- then the signer must be in the session's owner list (`OwnableValidator.sol` L349).

So code at the session EOA can authorise **that session only**, without the private key. ECDSA
paths cannot be influenced by delegated code. Another session's list does not contain the
hijacked EOA, and a code-less signer cannot verify. All of this is tested:

- `test_A_erc1271SignerHijack_anyoneCanDriveSession_withinPolicyOnly`: rejected before
  delegation, accepted after, still policy-bound;
- `test_A_cannotSwitchToAnotherSessionsPermissions`: three variants, all rejected.

**Revocation is independent of the compromised signer.** `removeSession` is a Safe transaction
(owner signatures, Safe nonce). The session cannot reach SmartSession
(`test_R_attackerCannotPreventRevocation`).

**Nothing signed before revocation executes after it:**

- `test_R_presignedOpsDieAndStayDead`: pre-signed ops for the next five nonces, ECDSA and
  hijacked, are rejected one by one as another session advances the shared nonce sequence;
- `test_R_emergencyUninstallKillsPresignedOps`: the same after uninstalling SmartSession;
- `test_C_revokedSession`, `test_A_leadershipRevocationEndsTheCompromise`.

**Exceptions:**

- **F4** (same key and salt re-enabled).
- Burning nonces is not revocation (`test_R_nonceBurnIsNotRevocation`).
- The attacker can still spend the remaining in-window budget *before* the revocation lands.
- If SmartSessions "enable mode" signatures were ever issued, revoke them with
  `SmartSession.revokeEnableSignature`. This template never issues them.

## 4. ERC-7562 compatibility (item 3)

**Method.**

1. Run `EntryPointSimulations.simulateValidation` (what bundlers execute).
2. Record the opcode trace (`vm.startDebugTraceRecording`) and keep the account-validation frame.
3. Evaluate it with the rules and association logic of Rhinestone's
   `erc4337-validation/SpecsParser.sol`: OP-011, OP-012, OP-080, STO-010/021, OP-041.
4. The harness lists **every** violation per contract. The unmodified upstream `Simulator`
   gives the pass/fail verdict.

| Configuration | Violations found | Upstream simulator | Test |
|---|---|---|---|
| Default session, ETH transfer | `OP-011 TIMESTAMP` and `OP-080 BALANCE (unstaked)`, **both in SpendingLimitPolicy** | rejects: `InvalidOpcode(SpendingLimitPolicy, 0x42)` | `test_7562_defaultSession_eth`, `…_upstreamSimulatorRejects` |
| Default session, ERC-20 transfer | `OP-011 TIMESTAMP` in SpendingLimitPolicy (the `balanceOf` read is associated storage, allowed) | rejects | `test_7562_defaultSession_erc20` |
| Everything **except** SpendingLimitPolicy (Safe, Safe7579, SmartSession, OwnableValidator, TimeFrame, SimpleGas, GasFeeCap, FunctionWhitelist, AddressWhitelist) | **none**: all storage associated, no banned opcodes | **accepts** | `test_7562_withoutSpendingLimit_*` |
| SimpleGasPolicy with split fees (only possible without GasFeeCapPolicy) | `OP-011 BASEFEE` in SimpleGasPolicy | — | `test_7562_simpleGasPolicyBasefeeOnlyInSplitFeeMode` |

**Qualifications.**

- This is a rule simulator, not a production bundler.
- OP-080 permits `BALANCE` for staked entities. Whether a staked account covers code it calls
  depends on the bundler.
- Bundlers differ in optional rules.
- Making SpendingLimitPolicy compliant needs a design without `TIMESTAMP`, e.g. time bounds
  returned as `validAfter`/`validUntil` like TimeFramePolicy. That is not implemented (no new
  functionality in this review).
- The private-bundler assumption remains, but it now applies to exactly one control.

## 5. Spending accounting (item 4)

- **Isolation:** usage is keyed by `ConfigId = f(account, permissionId, action)`, so one
  session's failed operations consume only its own budget
  (`test_I_failedOpsOnlyConsumeTheirOwnSession`). That includes a key-less third party griefing a
  hijacked session (`test_I_hijackedSessionGriefingStaysInsideThatSession`).
- **Cross-session effect:** F5 only.
- **Post-execution / reservation accounting: investigated, not adopted.**
  - Safe7579's hooks receive `(EntryPoint, value, execute-calldata)` (`ModuleManager._preHooks`),
    with no session identity.
  - SmartSessions rejects `executeUserOp` (SmartSession.sol L311, issue #17), so no execution path
    carries the permissionId.
  - A default-mode revert unwinds the hook too, so nothing can refund on failure.
  - A reservation keyed by bundle order (transient storage) would be fragile and is itself
    restricted by ERC-7562.
  - Every such design needs new, root-equivalent execution-phase code, and its failure mode is
    under-counting, i.e. a bypass. The template keeps validation-time accounting: it over-counts
    and never under-counts. `_hasBalance` and one-session-per-bundle reduce the over-count.

## 6. Privilege isolation (item 5)

- **Inventory** (`test_P_inventoryOfExecutionPaths`): one Safe module (Safe7579); no guard;
  one Safe7579 validator (SmartSession); no executors; no global hook; no hooks on `execute`,
  `executeFromExecutor`, `installModule` or `uninstallModule`; one session with no ERC-1271
  policies.
- **Sweep** (`test_P_sweepEveryStateChangingFunction`): all **66** state-changing functions of
  every deployed contract are taken from the compiled ABIs by `script/gen-admin-surface.sh`. The
  Safe7579 functions are attacked both through the Safe and on the singleton. Each is attempted
  via single `execute`, inside an otherwise valid batch, and as direct callData: **222 attempts**.
  All are rejected by a permission-level reason (`PolicyViolation`, `NoPoliciesSet`,
  `InvalidSelfCall`, `Unsupported*`) and through the real EntryPoint path, and the Safe is
  unchanged afterwards.
- **Property** (`testFuzz_P_anythingAcceptedIsAnAllowedTransfer`, 256 runs default / 5,001
  checked): every operation that passes validation is a native or ERC-20 transfer to a whitelisted
  beneficiary within the per-tx limit. The accepted branch was confirmed reachable.
- **Other surfaces:**
  - `Safe.simulateAndRevert` (public DELEGATECALL, always reverts):
    `test_P_simulateAndRevertCannotPersistState`;
  - direct calls to the adapter singleton: `test_P_directCallsToAdapterSingletonAffectOnlyTheCaller`;
  - earlier suites `PrivilegeEscalation.t.sol` and `Malicious7702Delegation.t.sol`.

## 7. Licensing (item 6)

`./script/check-licenses.sh` lists the SPDX tag of every source compiled into each deployed
contract.

| Component | Compiled sources | Notes |
|---|---|---|
| This repo's 4 policies (`src/`) | MIT only | Fixed in this review: `ISessionPolicy.sol` declares the ABI; `LicenseIsolation.t.sol` proves equality with upstream |
| Safe, SafeProxy, SafeProxyFactory, MultiSendCallOnly | LGPL-3.0-only | LICENSE file present |
| EntryPoint v0.7 | GPL-3.0 (+ LGPL, MIT) | `package.json` says ISC; LICENSE file and SPDX tags say GPL-3.0 |
| Safe7579 | GPL-3.0, LGPL-3.0-only, MIT; `IERC7579Module.sol` has **no SPDX** | `package.json` GPL-3.0; **no LICENSE file upstream** |
| SmartSession | **AGPL-3.0-only** (12 files), GPL, LGPL, MIT; `ISmartSession.sol` is **UNLICENSED** | no `license` field and **no LICENSE file upstream** |
| OwnableValidator | **AGPL-3.0-only** (itself and module-bases), GPL, MIT | `package.json` says GPL-3.0, conflicting with the file's AGPL-3.0-only |
| TimeFramePolicy, SimpleGasPolicy | MIT files that compile AGPL `DataTypes.sol` | |

**Obligations to evaluate with counsel:**

- AGPL-3.0 §13 (network interaction) for deployed SmartSession and OwnableValidator.
- GPL/LGPL source-availability obligations when distributing combined works.
- The `UNLICENSED` file and the files with no SPDX tag grant no explicit licence. Ask
  Rhinestone and Biconomy for clarification before redistributing those files.
- `test/` and `script/` are MIT-tagged but import these dependencies. They are development
  tooling, not deployed.

## 8. What is guaranteed, assumed, limited, or needs audit (item 7)

| | Statement | Evidence / reason |
|---|---|---|
| **Tested** | A session or its delegated code cannot alter owners, threshold, modules, guard, fallback handler, the adapter, sessions or policies, or reach any unrestricted execution path | §6, `PrivilegeEscalation.t.sol`, `Malicious7702Delegation.t.sol` |
| **Tested** | Value moves only as direct transfers to whitelisted beneficiaries, within per-tx and per-window limits, including batches and bundles | `PolicyEnforcement.t.sol`, property fuzz §6 |
| **Tested** | Gas outflow ≤ `gasCostLimit` per session configuration | §2 |
| **Tested** | Revocation is leadership-only, cannot be blocked by the session, and kills all pre-signed ops (except F4) | §3 |
| **Tested** | ERC-7562 violations are exactly those listed in §4 | §4 |
| **Assumption** | Leadership quorum honest; Safe has no other module, executor, hook or guard; whitelisted beneficiaries and tokens behave as expected; reused components correct | THREAT_MODEL §2 |
| **Known limitation** | Remaining budget is spendable by a compromised key before revocation; F3, F4, F5; private bundler needed for SpendingLimitPolicy; lifetime gas budget resets on re-initialisation | §2–§5 |
| **Needs production audit** | `SessionPolicyBase`, `TransferLib`, the four policies, `SessionSetup`, the deployment and configuration transactions, the bundler and key-management setup | unaudited code |

## 9. Out of scope / next

**Independent withdrawal authorization.** Exchanges pay previously unknown customer addresses.
The next extension is a separate module: every withdrawal carries an authorization for its exact
recipient, token, amount and nonce, from an independent signer, with aggregate limits enforced on
chain. That would replace the static beneficiary whitelist for that flow. It is deliberately not
part of this core, which should be published first as an explicitly unaudited reference.
