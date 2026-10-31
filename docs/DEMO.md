# The attack demonstration

`./script/demo.sh` runs the whole story on a local Ethereum chain (anvil, Prague hardfork, so
EIP-7702 is live). Nothing is mocked: every line is a real transaction. That includes the
leadership multisig, the session key's ERC-4337 operations, and the type-4 transaction that
installs the malicious delegation. Blocked attempts are mined and revert. For each one the
"Why" column names the on-chain control that stopped it.

| Act | What happens |
|---|---|
| 1 | The exchange pays whitelisted users through its session key. Payments outside its permissions are rejected. |
| 2 | The attacker steals the session key and uses EIP-7702 to replace the code at that address with [`MaliciousDelegation`](../src/examples/MaliciousDelegation.sol). |
| 3 | The malicious code tries 9 direct ways into the Safe, then tries to drain, add an owner, install a module and siphon gas fees through the session. All fail. A payment *within* the original permissions still works: that remaining budget is the bounded risk. |
| 4 | Leadership adds an owner and revokes the session. The stolen key is now useless. |

## Recorded run

```text
Setup: Safe owned by a 3-of-5 leadership multisig, holding 10 ETH and 1,000,000 USDC
  Safe          0x9C9DE1bedaD433757018d112853c46Bbb7A7bF74
  Session key   0x976EA74026E726554dB657fA54763abd0C3a0aa9  (Safe owner? false)
  Permissions   pay alice or bob only; max 1 ETH / 1,000 USDC per transfer; 5 ETH / 3,000 USDC per day

Act 1 - Normal operations: the exchange pays out through its session key
                                                       Expected Result Why
  Pay 1 ETH to alice (whitelisted)                     PASS     PASS   ok  [validation ok; tx status 0x1]
  Pay 1,000 USDC to bob (whitelisted)                  PASS     PASS   ok  [validation ok; tx status 0x1]
  Pay 1 ETH to an unknown address                      BLOCK    BLOCK  ok  [PolicyViolation by addressPolicy; tx status 0x0]
  Pay 2 ETH to alice (over the per-transfer limit)     BLOCK    BLOCK  ok  [PolicyViolation by spendingPolicy; tx status 0x0]

Act 2 - Compromise: the attacker steals the session key and installs EIP-7702 code
                                                       Expected Result Why
  Session key delegates its EOA to MaliciousDelegation PASS     PASS   ok  [type-4 tx; code 0x -> 0xef0100a51c1fc2...]
  The stolen key now controls code running at the session address. It does not control the Safe.

Act 3 - Attack: the malicious code tries to drain the Safe
                                                       Expected Result Why
    direct call: safe.execTransactionFromModule(ETH) -> rejected
    direct call: safe.execTransactionFromModule(ERC20) -> rejected
    direct call: safe.execTransaction(v=1 sigs) -> rejected
    direct call: safe7579.execute -> rejected
    direct call: safe7579.executeFromExecutor -> rejected
    direct call: token.transferFrom -> rejected
    direct call: safe.addOwnerWithThreshold -> rejected
    direct call: safe.enableModule -> rejected
    direct call: safe7579.installModule(executor) -> rejected
  Drain via 9 direct routes (module, owner sigs, ...)  BLOCK    BLOCK  ok  [0/9 succeeded]
  Drain 10 ETH to attacker through the session         BLOCK    BLOCK  ok  [PolicyViolation by addressPolicy; tx status 0x0]
  Add attacker as a Safe owner                         BLOCK    BLOCK  ok  [PolicyViolation by functionPolicy; tx status 0x0]
  Install an unrestricted module                       BLOCK    BLOCK  ok  [NoPoliciesSet (call route never granted); tx status 0x0]
  Siphon Safe ETH as inflated gas fees                 BLOCK    BLOCK  ok  [PolicyViolation by gasPolicy; tx status 0x0]
  Pay 1 ETH to alice (still within the permissions)    PASS     PASS   ok  [validation ok; tx status 0x1]
  A stolen key keeps exactly the permissions it was given - nothing more. That remaining budget is the bounded risk.

Act 4 - Leadership is still in control
                                                       Expected Result Why
  3-of-5 multisig adds a new owner                     PASS     PASS   ok  [owners now 6]
  3-of-5 multisig revokes the compromised session      PASS     PASS   ok  [session enabled: false]
  Compromised key tries again after revocation         BLOCK    BLOCK  ok  [InvalidPermissionId (session revoked); tx status 0x0]

Result
  Safe      8 ETH   999000 USDC   (started with 10 ETH / 1,000,000 USDC)
  alice     2 ETH        bob 1000 USDC   (legitimate, whitelisted payouts)
  attacker  0 ETH   0 USDC

Every step matched expectations: the attacker got nothing.
```

## Reproduce

```bash
pnpm install
./script/demo.sh          # about a minute; needs Foundry >= 1.0 and jq
```

To record a video of it: `asciinema rec -c ./script/demo.sh demo.cast`, or any screen recorder.
