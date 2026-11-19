# SafeNet sentinel from a Safe

A SafeNet sentinel posts a USDC.e bond on every transaction request it votes on, and gets the bond
plus a fee back when it votes with the outcome. This setup keeps that money in a **Safe** and gives
the sentinel server **one restricted key**. That key can make the Safe send the six sentinel
transactions and nothing else. Funds never sit on the server.

It applies the recommendation in [OPERATOR_KEY_COMPARISON.md §8](OPERATOR_KEY_COMPARISON.md#8-recommendation):
Zodiac Roles for the key, with Safe Policy Engine as the floor underneath.

> Proof of concept, not audited. `ERC20ApproveCapPolicy` and this copy of `OwnerOnlyPolicy` are new code.

## Why the sentinel has to be the Safe

`SentinelOracle` (safe-research/safenet @ `c355af1`) uses `msg.sender` as the sentinel's identity:

- `commit` pulls the bond from `msg.sender` and records the commitment under it.
- `reveal` checks the commitment of `msg.sender`. The commit hash includes the sentinel address, so a
  hash made with any other address fails at reveal (`test_finding_commitHashMustNameTheSafe`).
- `claim` pays bond and fee to `msg.sender`.

So the Safe itself must be the registered sentinel, and every call has to come from the Safe.

## What the key can do

The server key holds the Roles role `SENTINEL`. Per market (one fee token and its oracle):

| Call | Roles (the key's mandate) | Policy Engine (the floor) |
|---|---|---|
| `feeToken.approve(oracle, amount)` | spender = the oracle, amount ≤ 800 USDC.e | `ERC20ApproveCapPolicy`: same spender and cap |
| `oracle.commit` / `reveal` / `finalize` / `claim` / `timeoutArbitration` | allowed, no ETH value, no delegatecall | `AllowPolicy` |

The cap is enforced twice so that a misconfigured or compromised Roles module still can't approve
more than one bond (800 USDC.e is production's 0.40 fee × 2000 bond multiplier). Nothing else has an
engine entry, so it is denied for the key, for the Roles module and for the owners alike. That
includes moving funds, every other oracle function, delegatecall, MultiSend and any Safe or Roles
administration (the `test_block_*` tests, each tried three ways: through the key, as the module
itself, and with Roles deliberately opened up).

The owners keep a few owner-only entries, which no module can reach:

| Entry | Why |
|---|---|
| `Roles.assignRoles` | Rotate or revoke the server key |
| `Roles.scopeTarget`, `scopeFunction`, `allowFunction`, `revokeTarget` | Add or remove a market |
| `Safe.disableModule` | Emergency switch: detach Roles entirely |
| `Safe.swapOwner` | Owner replacement, at 4 of 5 (`IncreasedThresholdPolicy`) |
| `feeToken.transfer` to the treasury | Withdraw funds, to one fixed address only |

Without these, default-deny would lock the owners out of rotation once the guard is installed.

## Operations

**Rotate a key** (leaked, or an employee leaves): one owner transaction revokes the old key, a
second grants the new one. Both take effect immediately, with no engine delay and no governance step.
Requests the old key committed are revealed and claimed by the new key, because the commitment
belongs to the Safe (`test_rotation_*`).

**Add a fee token.** `FEE_TOKEN` is immutable in the oracle, so a new token always comes with a new
oracle: a new market. That takes a Policy Engine change (request, wait 1 day, apply) and then 8
single owner transactions on Roles (`SentinelSetup.rolesAddMarket`). The Roles side alone opens
nothing (`test_market_rolesAloneIsNotEnough`). Removal is `rolesRemoveMarket` (`test_market_remove`).

**Migrate an existing EOA sentinel to the Safe** (`test_migration_*`):

1. Governance calls `addSentinel(safe)`. In production this waits out the 51,840-block governance
   delay, about 3 days.
2. Switch the server to the Safe identity (see below).
3. Governance calls `removeSentinel(oldEoa)`. Removal only blocks new commits, so the EOA can still
   reveal and claim the requests it already committed to.

**Server changes this needs** (Safenet repository, not done here):

- Build commit hashes with the Safe's address instead of the signer's, and match the oracle's events
  against the Safe address.
- Send each action as `Roles.execTransactionWithRole(to, 0, data, 0, SENTINEL, true)` from the key,
  with gas headroom for the Roles and engine checks. `SentinelSetup.wrap` builds that calldata.

## Known limits

- **No budget across requests.** A leaked key can post an 800 USDC.e bond on every open request until
  it is revoked, and lose those bonds by not revealing. It can't send funds anywhere else
  (`test_finding_leakedKeyCanBondEveryRequestUntilRevoked`). A tighter cap of
  `800 + 800 × open arbitrations` is possible but not built.
- **The treasury entry admits modules.** Upstream `ERC20TransferPolicy` doesn't distinguish owner and
  module transactions, so a compromised Roles module could pay the treasury, and only the treasury
  (`test_finding_moduleCanReachTheTreasuryEntry`).
- **Deployment.** A new sentinel Safe can be deployed in one transaction from
  [safe-factory/examples/safenet-sentinel.json](../safe-factory/examples/safenet-sentinel.json)
  (see [safe-factory/](../safe-factory/)), with the same role key and mandate. Its admin entries also
  include Roles `revokeFunction` and `setAllowance`. The owner transactions for an existing Safe are
  in [`SentinelSetup`](../script/sentinel/SentinelSetup.sol).

## Tests

| Suite | What it runs |
|---|---|
| [SentinelSafe.t.sol](../test/sentinel/SentinelSafe.t.sol) | 28 tests on a local chain: setup, allowed paths, blocked paths, rotation, markets, migration, findings |
| [SentinelSafeFork.t.sol](../test/sentinel/SentinelSafeFork.t.sol) | The same 28 against Gnosis mainnet, plus 4 lifecycle tests on the production oracle and Consensus |

On the fork, the Safe, Roles and the Policy Engine are deployed fresh, and the production governance
address registers the Safe. A sponsor submits a transaction through `Consensus.proposeTransaction`.
The key then approves and commits, reveals, and the request is attested and claimed. Deny votes and the
dispute → `timeoutArbitration` → claim path are covered too. Validators attest with a threshold
signature that a fork can't produce, so only the coordinator's signature check is mocked; the rest of
`attestTransaction` runs for real. USDC.e balances are set with `deal`.

```bash
git submodule update --init lib/safenet          # SentinelOracle source
forge test --mc SentinelSafeTest                  # local
GNOSIS_RPC_URL=https://rpc.gnosischain.com pnpm test:fork:sentinel
# optional: FORK_BLOCK=<n> to pin a block (needs an archive RPC)
```

Without `GNOSIS_RPC_URL` the fork suite is skipped.

## Code

| Path | What |
|---|---|
| [script/sentinel/SentinelSetup.sol](../script/sentinel/SentinelSetup.sol) | Calldata the owners sign: Roles scopes, engine entries, guard install, `wrap` |
| [src/sentinel/ERC20ApproveCapPolicy.sol](../src/sentinel/ERC20ApproveCapPolicy.sol) | Engine policy: listed spender and amount cap per token |
| [src/sentinel/OwnerOnlyPolicy.sol](../src/sentinel/OwnerOnlyPolicy.sol) | Engine policy: owner transactions only, never a module |
| [test/sentinel/](../test/sentinel/) | Local and fork suites, plus artifact stubs for the GPL oracle and the LGPL engine |

The sentinel code shares no source files with the session-key template or the operator-key
comparison. SafeNet's `SentinelOracle` is GPL-3.0; it is compiled only in a test artifact stub and
reached through a local interface, so nothing in `src/` imports it.
