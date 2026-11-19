#!/usr/bin/env bash
# End to end on a local anvil chain, exactly as on a real one:
#   0. first run on a fresh anvil: installs the EIP-2470 factory (public chains have it) and stops
#   1. dry run of test/factory/fixtures/local.json (prints the Safe, sends nothing)
#   2. --broadcast from an account that is NOT an owner (shared contracts + one Safe creation)
#   3. the PAYOUTS key acts through Roles with `cast`: one allowed transfer, two refused
#   4. the script again: recognises the Safe, re-checks it, sends nothing
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT=${PORT:-8612}
RPC=http://127.0.0.1:$PORT
FIXTURE=test/factory/fixtures/local.json
DEPLOYER_PK=0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 # anvil account 9
KEY_PK=$(printf '0x%064x' 4)                                                  # the fixture's PAYOUTS key
ROLE=0x5041594f55545300000000000000000000000000000000000000000000000000      # bytes32("PAYOUTS")
USDC=0x1000000000000000000000000000000000000001
ALICE=0x00000000000000000000000000000000000A11cE

forge build --quiet
anvil --port "$PORT" --hardfork prague --silent &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null || true' EXIT
for _ in $(seq 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done

# The fixture's token and call target live at fixed addresses.
cast rpc --rpc-url "$RPC" anvil_setCode $USDC \
  "$(jq -r .deployedBytecode.object out/RestrictedSafeFactory.t.sol/FactoryToken.json)" >/dev/null
cast rpc --rpc-url "$RPC" anvil_setCode 0x1000000000000000000000000000000000000002 \
  "$(jq -r .deployedBytecode.object out/RestrictedSafeFactory.t.sol/Pinger.json)" >/dev/null

deploy() {
  forge script script/factory/DeployRestrictedSafe.s.sol --sig 'run(string)' "$FIXTURE" \
    --rpc-url "$RPC" "$@" 2>&1
}

echo "== 0. fresh anvil: the script installs the EIP-2470 factory Zodiac Roles needs, and asks for a rerun"
deploy | grep -o -m1 'local node: installed.*again' || true

echo "== 1. dry run"
deploy | grep -E 'DRY RUN|^  Safe  |^  Roles module|SIMULATION COMPLETE'

echo "== 2. broadcast"
OUT=$(deploy --broadcast --private-key "$DEPLOYER_PK")
echo "$OUT" | grep -E 'deployed and checked|^  Safe |ONCHAIN EXECUTION COMPLETE'
SAFE=$(echo "$OUT" | sed -n 's/^  Safe  *\(0x[0-9a-fA-F]*\)$/\1/p')
ROLES=$(echo "$OUT" | sed -n 's/^  Roles module  *//p')
B=broadcast/DeployRestrictedSafe.s.sol/31337/run-latest.json
echo "   $(jq '.receipts | length' $B) transactions; the Safe creation used $(cast to-dec "$(jq -r '.receipts[-1].gasUsed' $B)") gas"

echo "== 3. the key acts"
cast send "$USDC" 'mint(address,uint256)' "$SAFE" 100000000000 --private-key "$DEPLOYER_PK" --rpc-url "$RPC" >/dev/null
cast send "$(cast wallet address --private-key "$KEY_PK")" --value 1ether --private-key "$DEPLOYER_PK" --rpc-url "$RPC" >/dev/null
as_key() { # to data -> exit status of the key's transaction
  cast send "$ROLES" 'execTransactionWithRole(address,uint256,bytes,uint8,bytes32,bool)' \
    "$USDC" 0 "$1" 0 "$ROLE" true --private-key "$KEY_PK" --rpc-url "$RPC" >/dev/null 2>&1
}
as_key "$(cast calldata 'transfer(address,uint256)' $ALICE 1000000000)" || { echo "allowed transfer failed"; exit 1; }
echo "   1000 USDC to an allowed recipient: ok (balance $(cast call $USDC 'balanceOf(address)(uint256)' $ALICE --rpc-url "$RPC"))"
if as_key "$(cast calldata 'transfer(address,uint256)' 0x000000000000000000000000000000000000dEaD 1)"; then
  echo "transfer to an unlisted address went through"; exit 1
fi
echo "   1 USDC to an unlisted address: refused"
if as_key "$(cast calldata 'transfer(address,uint256)' $ALICE 1000000001)"; then
  echo "transfer above the per-transaction cap went through"; exit 1
fi
echo "   1000.000001 USDC (above the cap): refused"

echo "== 4. again"
deploy --broadcast --private-key "$DEPLOYER_PK" | grep -E 'already deployed|No transactions to broadcast'
echo "ok"
