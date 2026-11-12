#!/usr/bin/env bash
# Prints the SPDX licence of every source file compiled into each deployed contract (from the
# compiler metadata) and fails if a src/ contract compiles any non-permissive source.
# This is a factual inventory, not legal advice.
set -euo pipefail
cd "$(dirname "$0")/.."
forge build --quiet

OURS="FunctionWhitelistPolicy AddressWhitelistPolicy SpendingLimitPolicy GasFeeCapPolicy
  src/policies/engine/OwnerOnlyPolicy.sol:OwnerOnlyPolicy Safe7579BatchPolicy
  src/sentinel/OwnerOnlyPolicy.sol:OwnerOnlyPolicy src/sentinel/ERC20ApproveCapPolicy.sol:ERC20ApproveCapPolicy"
# Safe v1.4.1 (existing template) and v1.5.0 (operator-key comparison) share contract names, so
# those are fully qualified.
S141=node_modules/@safe-global/safe-contracts/contracts
S150=node_modules/@safe-global/safe-smart-account/contracts
UPSTREAM="$S141/Safe.sol:Safe $S141/proxies/SafeProxy.sol:SafeProxy $S141/proxies/SafeProxyFactory.sol:SafeProxyFactory
  $S141/libraries/MultiSendCallOnly.sol:MultiSendCallOnly
  $S150/Safe.sol:Safe $S150/proxies/SafeProxyFactory.sol:SafeProxyFactory $S150/libraries/MultiSendCallOnly.sol:MultiSendCallOnly
  Safe7579 EntryPoint SmartSession OwnableValidator TimeFramePolicy SimpleGasPolicy
  SafePolicyGuard ERC20TransferPolicy MultiSendPolicy IncreasedThresholdPolicy AllowedModulePolicy NativeTransferPolicy AllowPolicy
  Roles MultiSendUnwrapper ModuleProxyFactory"
PERMISSIVE='^(MIT|Apache-2\.0|\(Apache-2\.0 OR MIT\)|Apache-2\.0 OR MIT|MIT OR Apache-2\.0)$'
status=0

spdx() { grep -m1 -o 'SPDX-License-Identifier: *[^*]*' "$1" 2>/dev/null | sed 's/SPDX-License-Identifier: *//; s/[[:space:]]*$//' || true; }

sources() { # contract name, or <source path>:<name> for names that exist more than once
  if [[ "$1" == *:* ]]; then
    local src=${1%:*} name=${1##*:} j
    for j in $(find out -name "$name.json" -o -name "$name.*.json"); do
      if [[ $(jq -r '.metadata.settings.compilationTarget | keys[0]' "$j") == "$src" ]]; then
        jq -r '.metadata.sources | keys[]' "$j"
        return
      fi
    done
    echo "no artifact for $1" >&2
    return 1
  fi
  forge inspect "$1" metadata --json | jq -r '.sources | keys[]'
}

report() { # contract
  sources "$1" | while read -r f; do
    l=$(spdx "$f"); echo "${l:-<none>}|$f"
  done
}

echo "== This repository (must compile permissive sources only)"
for c in $OURS; do
  bad=$(report "$c" | awk -F'|' -v re="$PERMISSIVE" '$1 !~ re')
  if [[ -n "$bad" ]]; then status=1; echo "  $c: NON-PERMISSIVE SOURCES"; echo "$bad" | sed 's/^/      /'
  else echo "  $c: ok ($(report "$c" | cut -d'|' -f1 | sort | uniq -c | xargs))"; fi
done

echo
echo "== Reused, deployed components (licence mix of the compiled sources)"
for c in $UPSTREAM; do
  echo "  ${c#node_modules/}: $(report "$c" | cut -d'|' -f1 | sort | uniq -c | xargs)"
done
exit $status
