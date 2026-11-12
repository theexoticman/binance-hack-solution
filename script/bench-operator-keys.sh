#!/usr/bin/env bash
# Deploys and exercises both restricted operator-key architectures on a local anvil chain and
# prints the gas of every transaction, from the broadcast receipts.
#
#   ./script/bench-operator-keys.sh                  # operator signs with a local key
#   OPERATOR_SIGNER=wallet ./script/bench-operator-keys.sh
#       # operator signs through forge's wallet layer (vm.sign(address, digest)) - the code path
#       # used with --aws / --gcp / --ledger; here backed by --private-keys
#
# Requirements: foundry >= 1.0, jq. Never run against a public network: it signs owner
# transactions with anvil's well-known keys.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-8547}
RPC="http://127.0.0.1:$PORT"
MNEMONIC="test test test test test test test test test test test junk"
DEPLOYER_PK=$(cast wallet private-key --mnemonic "$MNEMONIC" --mnemonic-index 0)
OPERATOR_PK=$(cast wallet private-key --mnemonic "$MNEMONIC" --mnemonic-index 6)
OPERATOR2_PK=$(cast wallet private-key --mnemonic "$MNEMONIC" --mnemonic-index 7)
BROADCAST=broadcast/DeployOperatorKeys.s.sol/31337
OUT=deployments/operator-keys-gas.txt

command -v jq >/dev/null || { echo "jq is required"; exit 1; }
forge build --quiet

anvil --hardfork prague --port "$PORT" --silent &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null || true' EXIT
for _ in $(seq 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done

WALLET_ARGS=()
if [[ "${OPERATOR_SIGNER:-local}" == "wallet" ]]; then
  WALLET_ARGS=(--private-keys "$DEPLOYER_PK" --private-keys "$OPERATOR_PK" --private-keys "$OPERATOR2_PK")
fi

phase() {
  echo "-> $1" >&2
  if ! forge script script/DeployOperatorKeys.s.sol --sig "$1()" --rpc-url "$RPC" --broadcast --slow \
    ${WALLET_ARGS[@]+"${WALLET_ARGS[@]}"} >"deployments/operator-keys-$1.log" 2>&1; then
    tail -30 "deployments/operator-keys-$1.log" >&2
    exit 1
  fi
}

PHASES=(shared zodiacSingletons sessionsSingletons zodiacSafe sessionsSafe fund
  zodiacConfigure sessionsConfigure zodiacExec sessionsExec zodiacBatch sessionsBatch
  zodiacRotate sessionsRotate zodiacRevoke sessionsRevoke)
for p in "${PHASES[@]}"; do
  phase "$p"
done

# receipts carry quantities as hex strings
HEX='def hex: ltrimstr("0x") | ascii_downcase | explode
  | reduce .[] as $c (0; . * 16 + (if $c >= 97 then $c - 87 else $c - 48 end));'

{
  echo "# Receipt gas per transaction (anvil, Prague, $(forge --version | head -1))"
  echo "# operator signer: ${OPERATOR_SIGNER:-local}"
  for p in "${PHASES[@]}"; do
    f="$BROADCAST/$p-latest.json"
    total=$(jq "$HEX"' [.receipts[].gasUsed | hex] | add' "$f")
    echo
    echo "## $p  (total $total)"
    jq -r "$HEX"'
      [.transactions, .receipts] | transpose[] |
      "\(.[1].gasUsed | hex)\t\(.[0].transactionType)\t\(.[0].contractName // "-")\t\(.[0].function // "-")\tstatus=\(.[1].status)"
    ' "$f"
  done
} | tee "$OUT"

# Every receipt must have succeeded.
if grep -q "status=0x0" "$OUT"; then
  echo "A transaction FAILED (status 0x0)" >&2
  exit 1
fi
echo
echo "Written to $OUT"
