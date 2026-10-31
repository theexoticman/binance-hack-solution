#!/usr/bin/env bash
# The attack demonstration, on a local anvil chain (Prague / EIP-7702).
#
#   Act 1  the exchange operates normally through a restricted session key
#   Act 2  the session key is stolen; the attacker installs a malicious EIP-7702 delegation
#   Act 3  the attacker tries to drain the Safe and escalate privileges - every attempt fails
#   Act 4  leadership is still in control and revokes the session
#
# Every step is a real transaction. Blocked operations are mined and revert; for each one the
# script also prints which on-chain control stopped it (SmartSession's exact revert reason).
#
# Usage: ./script/demo.sh            (requires foundry >= 1.0 and jq)
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8545}"
RPC="http://127.0.0.1:${PORT}"
MNEMONIC="test test test test test test test test test test test junk"
RELAYER_PK=$(cast wallet private-key "$MNEMONIC" 0)
SESSION_PK=$(cast wallet private-key "$MNEMONIC" 6)
ENTRYPOINT=0x0000000071727De22E5E9d8BAf0edAc6f37da032
FAILURES=0

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
row() { printf '  %-52s %-8s %-6s %s\n' "$1" "$2" "$3" "$4"; }
act() { echo; bold "$*"; row "" "Expected" "Result" "Why"; }
say() { printf '  \033[2m%s\033[0m\n' "$*"; }
check() { # expected actual
  if [[ "$1" == "$2" ]]; then echo "ok"; else FAILURES=$((FAILURES + 1)); echo "MISMATCH"; fi
}

# ---------------------------------------------------------------- chain
if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "Something is already listening on $RPC - stop it or set PORT=..." >&2
  exit 1
fi
anvil --hardfork prague --port "$PORT" --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
for _ in $(seq 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

bold "Setup: Safe owned by a 3-of-5 leadership multisig, holding 10 ETH and 1,000,000 USDC"
forge build --quiet
mkdir -p deployments
forge script script/DeployDemo.s.sol --rpc-url "$RPC" --broadcast --slow --quiet >/dev/null
J=deployments/demo.json
get() { jq -r ".$1" "$J"; }
SAFE=$(get safe); SMART_SESSION=$(get smartSession); USDC=$(get usdc); SESSION=$(get sessionKey)
ATTACKER=$(get attacker); MALICIOUS=$(get malicious)
say "Safe          $SAFE"
say "Session key   $SESSION  (Safe owner? $(cast call "$SAFE" 'isOwner(address)(bool)' "$SESSION" --rpc-url "$RPC"))"
say "Permissions   pay alice or bob only; max 1 ETH / 1,000 USDC per transfer; 5 ETH / 3,000 USDC per day"
policy_name() {
  local a; a=$(echo "$1" | tr 'A-F' 'a-f')
  for p in functionPolicy addressPolicy spendingPolicy timeFramePolicy gasPolicy gasFeeCapPolicy; do
    [[ "$(get "$p" | tr 'A-F' 'a-f')" == "$a" ]] && { echo "$p"; return; }
  done
  echo "$1"
}

# Decode the SmartSession revert reason returned by eth_call(validateUserOp) from the Safe.
diagnose() {
  local out data sel
  if out=$(cast call "$SMART_SESSION" "$(cat deployments/validate.hex)" --from "$SAFE" --rpc-url "$RPC" 2>&1); then
    echo "validation ok"; return
  fi
  data=$(echo "$out" | grep -oE '0x[0-9a-fA-F]{8,}' | tail -1 || true)
  sel=${data:0:10}
  case "$sel" in
    "$(cast sig 'PolicyViolation(bytes32,address)')") echo "PolicyViolation by $(policy_name "0x${data: -40}")" ;;
    "$(cast sig 'NoPoliciesSet(bytes32)')") echo "NoPoliciesSet (call route never granted)" ;;
    "$(cast sig 'InvalidPermissionId(bytes32)')") echo "InvalidPermissionId (session revoked)" ;;
    *) echo "revert ${data:-$out}" ;;
  esac
}

# Build a signed userOp for a scenario, diagnose it, then submit it for real (fixed gas => mined).
user_op() { # label scenario expected sender_pk
  local label=$1 scenario=$2 expected=$3 pk=${4:-$RELAYER_PK} reason status result
  forge script script/DeployDemo.s.sol --sig "userOp(string)" "$scenario" --rpc-url "$RPC" --quiet >/dev/null
  reason=$(diagnose)
  status=$(cast send "$ENTRYPOINT" "$(cat deployments/op.hex)" --private-key "$pk" --gas-limit 3000000 \
    --rpc-url "$RPC" --json 2>/dev/null | jq -r .status)
  [[ "$status" == "0x1" ]] && result=PASS || result=BLOCK
  row "$label" "$expected" "$result" "$(check "$expected" "$result")  [$reason; tx status $status]"
}

eth() { cast balance "$1" --rpc-url "$RPC" --ether | awk '{printf "%g", $1}'; }
usdc() { cast call "$USDC" 'balanceOf(address)(uint256)' "$1" --rpc-url "$RPC" | awk '{print $1/1e6}'; }

act "Act 1 - Normal operations: the exchange pays out through its session key"
user_op "Pay 1 ETH to alice (whitelisted)" valid-eth PASS
user_op "Pay 1,000 USDC to bob (whitelisted)" valid-usdc PASS
user_op "Pay 1 ETH to an unknown address" unauthorized-recipient BLOCK
user_op "Pay 2 ETH to alice (over the per-transfer limit)" over-limit BLOCK

act "Act 2 - Compromise: the attacker steals the session key and installs EIP-7702 code"
CODE_BEFORE=$(cast code "$SESSION" --rpc-url "$RPC")
TX=$(cast send "$SESSION" --auth "$MALICIOUS" --private-key "$SESSION_PK" --gas-limit 200000 --rpc-url "$RPC" --json)
CODE=$(cast code "$SESSION" --rpc-url "$RPC" | tr 'A-F' 'a-f')
EXPECTED_CODE="0xef0100$(echo "${MALICIOUS:2}" | tr 'A-F' 'a-f')"
[[ "$CODE" == "$EXPECTED_CODE" ]] && DELEG=PASS || DELEG=BLOCK
row "Session key delegates its EOA to MaliciousDelegation" PASS "$DELEG" "$(check PASS "$DELEG")  [type-$(echo "$TX" | jq -r .type | sed 's/0x//') tx; code $CODE_BEFORE -> ${CODE:0:16}...]"
say "The stolen key now controls code running at the session address. It does not control the Safe."

act "Act 3 - Attack: the malicious code tries to drain the Safe"
TX=$(cast send "$SESSION" 'drainAll(address,address,address)' "$SAFE" "$USDC" "$ATTACKER" \
  --private-key "$SESSION_PK" --gas-limit 3000000 --rpc-url "$RPC" --json)
TOPIC=$(cast keccak 'AttackAttempt(string,bool,bytes)')
SUCCESSES=0
while read -r data; do
  route=$(cast decode-abi 'f()(string,bool,bytes)' "$data" | sed -n 1p | tr -d '"')
  ok=$(cast decode-abi 'f()(string,bool,bytes)' "$data" | sed -n 2p)
  [[ "$ok" == "true" ]] && SUCCESSES=$((SUCCESSES + 1))
  say "  direct call: $route -> $([[ "$ok" == true ]] && echo SUCCEEDED || echo rejected)"
done < <(echo "$TX" | jq -r --arg t "$TOPIC" '.logs[] | select(.topics[0] == $t) | .data')
[[ "$SUCCESSES" == 0 ]] && DRAIN=BLOCK || DRAIN=PASS
row "Drain via 9 direct routes (module, owner sigs, ...)" BLOCK "$DRAIN" "$(check BLOCK "$DRAIN")  [$SUCCESSES/9 succeeded]"
user_op "Drain 10 ETH to attacker through the session" drain BLOCK "$SESSION_PK"
user_op "Add attacker as a Safe owner" add-owner BLOCK "$SESSION_PK"
user_op "Install an unrestricted module" install-module BLOCK "$SESSION_PK"
user_op "Siphon Safe ETH as inflated gas fees" fee-extraction BLOCK "$SESSION_PK"
user_op "Pay 1 ETH to alice (still within the permissions)" valid-eth PASS "$SESSION_PK"
say "A stolen key keeps exactly the permissions it was given - nothing more. That remaining budget is the bounded risk."

act "Act 4 - Leadership is still in control"
forge script script/DeployDemo.s.sol --sig "leadershipAddOwner()" --rpc-url "$RPC" --broadcast --quiet >/dev/null
OWNERS=$(cast call "$SAFE" 'getOwners()(address[])' --rpc-url "$RPC" | tr ',' '\n' | wc -l | tr -d ' ')
[[ "$OWNERS" == 6 ]] && ADMIN=PASS || ADMIN=BLOCK
row "3-of-5 multisig adds a new owner" PASS "$ADMIN" "$(check PASS "$ADMIN")  [owners now $OWNERS]"
forge script script/DeployDemo.s.sol --sig "leadershipRevokeSession()" --rpc-url "$RPC" --broadcast --quiet >/dev/null
ENABLED=$(cast call "$SMART_SESSION" 'isPermissionEnabled(bytes32,address)(bool)' "$(get permissionId)" "$SAFE" --rpc-url "$RPC")
[[ "$ENABLED" == false ]] && REVOKED=PASS || REVOKED=BLOCK
row "3-of-5 multisig revokes the compromised session" PASS "$REVOKED" "$(check PASS "$REVOKED")  [session enabled: $ENABLED]"
user_op "Compromised key tries again after revocation" valid-eth BLOCK "$SESSION_PK"

echo
bold "Result"
say "Safe      $(eth "$SAFE") ETH   $(usdc "$SAFE") USDC   (started with 10 ETH / 1,000,000 USDC)"
say "alice     $(eth "$(get alice)") ETH        bob $(usdc "$(get bob)") USDC   (legitimate, whitelisted payouts)"
say "attacker  $(eth "$ATTACKER") ETH   $(usdc "$ATTACKER") USDC"
echo
if [[ "$FAILURES" == 0 ]]; then bold "Every step matched expectations: the attacker got nothing."; else bold "$FAILURES scenario(s) did NOT match expectations."; exit 1; fi
