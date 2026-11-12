# Contributing

Thanks for taking a look. This is a security reference, so the bar for changes is mostly about
evidence: every claim in the docs should point at a test, and every new control should come with
tests that try to break it.

Contributions that help the most:

- **A new attack path**: a way a stolen session key (or code it installs with EIP-7702) might
  get around the policies. If it works, report it privately first (see [SECURITY.md](SECURITY.md)).
  If it is blocked, a test showing that is still a useful contribution.
- **A new policy**: follow [docs/ADDING_POLICIES.md](docs/ADDING_POLICIES.md).
- **Doc fixes**: anything unclear, wrong or out of date.

For anything larger than a small fix, please open an issue first so we can agree on the approach
before you spend time on it.

## Workflow

1. **Fork** the repository on GitHub and clone your fork:

   ```bash
   git clone https://github.com/<your-username>/binance-hack-solution.git
   cd binance-hack-solution
   git remote add upstream https://github.com/theexoticman/binance-hack-solution.git
   ```

2. **Create a branch** from an up-to-date `main`:

   ```bash
   git fetch upstream
   git switch -c fix/short-description upstream/main
   ```

   Use a prefix that says what the branch is: `fix/`, `feat/`, `test/`, `docs/`.

3. **Make your change** and run the checks below.

4. **Commit** in small, focused commits. Write the subject line in the imperative ("Add
   business-hours policy", not "Added..."), and explain *why* in the body when it isn't obvious.

5. **Push** to your fork and **open a pull request** against `main`. Fill in the PR template:
   what changed, why, and which tests cover it.

6. **Review.** CI must pass. Expect questions, especially on anything in `src/`. Address feedback
   with new commits; they will be squashed when merging.

Keep your branch current with `git fetch upstream && git rebase upstream/main` rather than merge
commits.

## Setup

You need [Foundry](https://getfoundry.sh) ≥ 1.0, [pnpm](https://pnpm.io) and `jq`.

```bash
git submodule update --init lib/safenet   # SafeNet sources for the sentinel tests
pnpm install    # Solidity dependencies, pinned in pnpm-lock.yaml
pnpm build
```

Dependencies are installed with `ignore-scripts=true` (see `.npmrc`): they are Solidity sources
only and never need to run install scripts.

## Checks to run before opening a PR

CI runs all of these. Running them locally first saves a round trip.

```bash
forge fmt --check            # formatting (run `forge fmt` to fix)
pnpm test                    # full suite, including the ERC-7562 tracer tests
./script/check-licenses.sh   # src/ must compile only MIT/Apache sources
./script/demo.sh             # end-to-end demo on a local anvil chain
```

If you touch the sentinel, also run its fork suite against Gnosis mainnet:
`GNOSIS_RPC_URL=<rpc> pnpm test:fork:sentinel`. CI runs it only when the repository has that
secret. If you change the operator-key comparison, rerun `pnpm gas:operator-keys` and commit the
updated `snapshots/`.

If you add a deployed contract, change a contract's external functions or update dependencies,
run `./script/gen-admin-surface.sh` to regenerate `test/utils/AdminSurface.sol`. That file lists
every state-changing function that `test/PrivilegeIsolation.t.sol` attacks. A new contract also
needs to be added to the `CONTRACTS` list at the top of the script.

## Tests

Test names carry a letter that says which question they answer:

| Prefix | File | Question |
|---|---|---|
| `test_A_` | `Malicious7702Delegation.t.sol` | Does an EIP-7702 delegation of the session key give the attacker anything extra? |
| `test_B_` | `PrivilegeEscalation.t.sol` | Can the session key change owners, modules, sessions or policies? |
| `test_C_` | `PolicyEnforcement.t.sol` | Can the legitimate session key get around its own policies? |
| `test_D_`, `test_E_` | `SessionExecution.t.sol` | Do normal operations work, and does leadership keep root authority? |
| `test_I_` | `AccountingIsolation.t.sol` | Can one session's failures consume another session's budget? |
| `test_P_` | `PrivilegeIsolation.t.sol` | Is every state-changing function of every contract unreachable from a session? |
| `test_R_` | `Revocation.t.sol` | Does revocation work without the compromised key, and kill pre-signed ops? |
| `test_L_` | `LicenseIsolation.t.sol` | Are the MIT interfaces ABI-identical to upstream? |
| `test_gas_` | `GasAccounting.t.sol` | Is the Safe's gas outflow bounded by the session's gas budget? |
| `test_7562_` | `Erc7562Compliance.t.sol` | Which contracts break the ERC-4337 mempool rules? |

The operator-key comparison and the sentinel have their own suites:

| Prefix | Location | Question |
|---|---|---|
| `test_S01_` … `test_S22_` | `test/operator-keys/OperatorKeySuite.sol` | The shared scenarios, run against both architectures |
| `test_A_`, `test_B_` | `test/operator-keys/ZodiacRoles.t.sol`, `SmartSessions*.t.sol` | Behaviour specific to Roles (A) or Smart Sessions (B) |
| `test_gas_` | `test/operator-keys/OperatorKeyGas.t.sol` | Gas of both, for `snapshots/` |
| `test_setup_`, `test_allow_`, `test_block_`, `test_rotation_`, `test_market_`, `test_migration_`, `test_finding_` | `test/sentinel/SentinelSafe.t.sol` | The sentinel Safe, by topic |
| `test_fork_` | `test/sentinel/SentinelSafeFork.t.sol` | The sentinel against production SafeNet on Gnosis |

New tests go in the file whose question they answer, using its prefix. Most tests inherit
[`test/utils/SessionTestBase.sol`](test/utils/SessionTestBase.sol), which deploys the real Safe,
Safe7579, EntryPoint, SmartSession and policies.

For a rejected operation, use `_assertRejectedInValidation(op, exactReason)`. A bare
`vm.expectRevert()` passes for any failure, including a broken setup, so it says nothing about
which control stopped the operation.

## Changes to `src/`

The contracts in `src/` are the code an auditor would review, so changes there get the most
scrutiny:

- Follow the rules in [docs/ADDING_POLICIES.md §2](docs/ADDING_POLICIES.md#2-implement):
  namespace state, fail closed, decode strictly, no trust in `msg.sender` or `tx.origin`.
- Import only the MIT interfaces (`src/interfaces/` for the template and the comparison,
  `src/sentinel/ISafePolicy.sol` for the sentinel) and permissively licensed code. The license
  check fails otherwise. The sentinel shares no sources with the other two parts; keep it that way.
- Include a positive test (the allowed case works) and negative tests with exact revert reasons.
- Update the docs that describe the behaviour you changed: `ARCHITECTURE.md`, `THREAT_MODEL.md`
  or `SECURITY_REVIEW.md`.

## Style

- Solidity is formatted with `forge fmt` using the settings in `foundry.toml`.
- Prefer clarity over cleverness. Comments should explain *why* a check exists, not repeat what
  the code does.
- In docs, state what is tested and name the test. Don't claim something is safe without one.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
