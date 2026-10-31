# Adding a Policy

A policy is a contract that SmartSession calls during ERC-4337 validation for every execution of
a session (every element of a batch included). It returns allow or deny. It can never grant
anything: it holds no authority over the Safe and cannot bypass the other policies, because
SmartSession requires **all** of a session's policies to pass.

## 1. Pick the right hook

| You want to restrict… | Interface | Called with | Example |
|---|---|---|---|
| each execution (target, value, calldata) | `IActionPolicy` | `checkAction(id, account, target, value, data)` | the three policies in `src/policies/` |
| the user operation as a whole (time, gas, paymaster) | `IUserOpPolicy` | `checkUserOpPolicy(id, userOp)` | `TimeFramePolicy`, `SimpleGasPolicy`, `GasFeeCapPolicy` |
| ERC-1271 signatures made *as the Safe* | `I1271Policy` | `check1271SignedAction(...)` | none enabled in this template |
| the **outcome** of execution (post-state) | not a policy: execution phase | see §6 | — |

Most new controls (rate limits, token allowlists, time windows, protocol argument checks) are
action policies. Extend `SessionPolicyBase`.

## 2. Implement

`SessionPolicyBase` handles namespacing, epochs and fail-closed initialisation. You write two
functions:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ConfigId } from "../interfaces/ISessionPolicy.sol";
import { SessionPolicyBase } from "./SessionPolicyBase.sol";

/// Example: only allow operations during a daily UTC window (e.g. 08:00-20:00).
contract BusinessHoursPolicy is SessionPolicyBase {
    struct Window { uint32 startSecond; uint32 endSecond; }

    error InvalidWindow();

    // window[configId][multiplexer][epoch][account] - account is the innermost key (ERC-7562)
    mapping(ConfigId => mapping(address => mapping(uint256 => mapping(address => Window)))) internal $window;

    function _configure(ConfigId id, address multiplexer, address account, uint256 epoch, bytes calldata initData)
        internal
        override
    {
        Window memory w = abi.decode(initData, (Window));
        if (w.startSecond >= w.endSecond || w.endSecond > 1 days) revert InvalidWindow();
        $window[id][multiplexer][epoch][account] = w;
    }

    function _check(ConfigId id, address multiplexer, address account, uint256 epoch, address, uint256, bytes calldata)
        internal
        view
        override
        returns (bool)
    {
        Window memory w = $window[id][multiplexer][epoch][account];
        uint256 t = block.timestamp % 1 days;
        return t >= w.startSecond && t < w.endSecond;
    }
}
```

Rules (also in `src/interfaces/ISessionPolicy.sol`):

1. **Namespace everything** by `(id, multiplexer, …, account)`. Never key state by `target` or
   `tx.origin` alone. Anyone can call your policy directly.
2. **Key configuration by `epoch`.** Then re-initialisation replaces the config, and removed
   entries disappear. Do *not* epoch-key usage counters that must survive reconfiguration (see
   `SpendingLimitPolicy`).
3. **Fail closed.** Unknown calldata shapes, unknown assets and missing config return `false` (or
   revert). If you decode calldata, decode strictly (exact length, clean padding). Reuse
   `TransferLib` for asset movements.
4. **Never trust `msg.sender`/`tx.origin` for authorisation** inside `_check`: `msg.sender` is
   SmartSession, and `tx.origin` is whoever bundles.
5. **Avoid external calls**, especially state-changing ones. If you must read external state, use
   `staticcall` and treat failure as deny.
6. **Stateful policies record usage in validation.** A later execution revert does not undo it.
   Make sure that over-counting is acceptable.
7. Validation-phase opcodes such as `TIMESTAMP` violate ERC-7562 for public mempools. That is
   fine with your own bundler; document it, and check it with `test/Erc7562Compliance.t.sol`
   (`forge test --mc Erc7562ComplianceTest -vvv`).
8. **Import only `../interfaces/ISessionPolicy.sol`** (plus `forge-std` / permissive libraries).
   SmartSessions and ERC-4337 sources are AGPL/GPL/LGPL, and `./script/check-licenses.sh` fails if
   a `src/` contract compiles them.

## 3. Test

Inherit `test/utils/SessionTestBase.sol`. It deploys the real Safe, Safe7579, EntryPoint,
SmartSession and policies, and creates a session.

```solidity
contract BusinessHoursPolicyTest is SessionTestBase {
    BusinessHoursPolicy hours_;

    function setUp() public override {
        super.setUp();
        hours_ = new BusinessHoursPolicy();
        // Leadership adds the policy to the session's catch-all action (alongside the existing three).
        _reconfigure(address(hours_), abi.encode(BusinessHoursPolicy.Window(8 hours, 20 hours)));
    }

    function test_blockedAtNight() public {
        vm.warp(block.timestamp - (block.timestamp % 1 days) + 22 hours);
        _assertRejectedInValidation(_sessionOp(_singleCall(alice, 1 ether, "")), _policyViolation(address(hours_)));
    }

    function test_allowedDuringDay() public {
        vm.warp(block.timestamp - (block.timestamp % 1 days) + 12 hours);
        _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        assertEq(alice.balance, 1 ether);
    }
}
```

Always include:

- a **positive control** (an allowed op passes, so the setup is sound);
- each **negative case** through `_assertRejectedInValidation(op, exactReason)`, which proves the
  op reached *your* policy and that the real EntryPoint path rejects it;
- **direct-call tampering**: call `initializeWithMultiplexer`/`checkAction` directly from an
  attacker and show the real config is unchanged;
- **batches**: one bad element in a batch must reject the whole op;
- **reconfiguration**: re-initialising behaves as documented (replace vs accumulate);
- a quick **mutation check**: break your core condition, run `forge test`, and confirm that tests fail.

## 4. Register (deploy)

Policies are stateless singletons: deploy once per chain and share them across Safes and
sessions. Namespacing isolates them. There is no on-chain registry in this template.
SmartSessions' `ConfigLib` checks ERC-165 (`supportsInterface`) when a policy is enabled.
`SessionPolicyBase` reports `IPolicy` and `IActionPolicy`. For production, consider an ERC-7484
module registry with attestations, and pin policy addresses in your deployment configuration.

## 5. Assign to a session

Only the Safe can configure its sessions, so assigning a policy is a leadership multisig
transaction:

- **New session:** add a `PolicyData{policy, initData}` to the catch-all action's
  `actionPolicies` in `SessionSetup.exchangeSession` (or your own builder), then call
  `SmartSession.enableSessions`.
- **Existing session:** call `SmartSession.enableActionPolicies(permissionId, [ActionData{FALLBACK_TARGET_SELECTOR_FLAG, FALLBACK_TARGET_FLAG, [PolicyData]}])`.
  Policies are *added* to the action's set. Policies already in it are re-initialised with the new
  `initData`.
- **Remove:** `SmartSession.disableActionPolicies(permissionId, actionId, [policy])`. Removing all
  policies from the action disables it, which makes every execution fail (`NoPoliciesSet`).
- **User-op policies:** `SmartSession.enableUserOpPolicies(permissionId, [PolicyData])`.

A session's permissionId does not depend on its policies, so assigning policies never changes
the key's identity.

## 6. Controls that need the execution phase

Validation-time policies see calldata, not results. Several controls on the list need post-state
or exact accounting:

- *transaction-outcome assertions* (e.g. "Safe balance of X decreased by at most N", "health
  factor ≥ 1.5", "no debt opened");
- *successful-only accounting* (refund the budget if execution reverts);
- *asset-flow restrictions* through arbitrary protocols.

These belong in an **ERC-7579 hook** installed on Safe7579 (`preCheck`/`postCheck` around
`execute`), or in a dedicated **guarded executor** such as ZyFAI's GuardedExec. Either is
**root-equivalent code**: a buggy hook can block all sessions, and an executor can execute
without any session policy. Treat it as a security-critical upgrade: leadership installs it,
it is audited, and it is not upgradeable by anyone but the Safe. This template ships neither,
which keeps the trusted surface small.

## 7. Checklist

- [ ] Inherits `SessionPolicyBase` (or implements `IPolicy` and the right check interface with the same rules)
- [ ] State namespaced by `(id, multiplexer, account)`, with account innermost
- [ ] Config epoch-keyed; usage semantics on reconfiguration documented
- [ ] Unknown inputs fail; strict decoding
- [ ] No reliance on `msg.sender`/`tx.origin` for authorisation; no state-changing external calls
- [ ] Tests: positive control, exact-reason negatives, tampering, batch, reconfiguration, mutation check
- [ ] ERC-7562 implications documented
- [ ] Independent review before production use
