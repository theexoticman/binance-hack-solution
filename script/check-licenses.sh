#!/usr/bin/env bash
# Prints the SPDX licence of every source file compiled into each deployed contract (from the
# compiler metadata) and fails if a src/ contract compiles any non-permissive source.
# This is a factual inventory, not legal advice.
set -euo pipefail
cd "$(dirname "$0")/.."
forge build --quiet

OURS="FunctionWhitelistPolicy AddressWhitelistPolicy SpendingLimitPolicy GasFeeCapPolicy"
UPSTREAM="Safe SafeProxy SafeProxyFactory MultiSendCallOnly Safe7579 EntryPoint SmartSession OwnableValidator TimeFramePolicy SimpleGasPolicy"
PERMISSIVE='^(MIT|Apache-2\.0|\(Apache-2\.0 OR MIT\)|Apache-2\.0 OR MIT|MIT OR Apache-2\.0)$'
status=0

spdx() { grep -m1 -o 'SPDX-License-Identifier: *[^*]*' "$1" 2>/dev/null | sed 's/SPDX-License-Identifier: *//; s/[[:space:]]*$//' || true; }

report() { # contract
  forge inspect "$1" metadata --json | jq -r '.sources | keys[]' | while read -r f; do
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
  echo "  $c: $(report "$c" | cut -d'|' -f1 | sort | uniq -c | xargs)"
done
exit $status
