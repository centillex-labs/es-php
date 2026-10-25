#!/usr/bin/env bash
# CVE-2016-7124 regression: patched builds wipe the broken object, unpatched
# builds leave it reachable. 5.6 already carries the upstream fix, so its
# baseline is expected to look patched -- that is reported, not hidden.
set -uo pipefail
cd "$(dirname "$0")/../.."
branches=("$@")
[ ${#branches[@]} -eq 0 ] && branches=(5.4 5.5 5.6)
status=0
for b in "${branches[@]}"; do
  base_expect=vulnerable
  [ "$b" = 5.6 ] && base_expect=fixed
  fixed="work/reports/php-${b}-unserialize-7124-fixed.json"
  base="work/reports/php-${b}-unserialize-7124-baseline.json"
  python3 tests/unserialize-broken-object/run.py --image "es-php:${b}-test" \
    --expect fixed --report "$fixed" >/dev/null
  rc_fixed=$?
  python3 tests/unserialize-broken-object/run.py --image "es-php:${b}-baseline" \
    --expect "$base_expect" --report "$base" >/dev/null
  rc_base=$?
  if [ "$rc_fixed" -eq 0 ] && [ "$rc_base" -eq 0 ]; then
    echo "OK   ${b}: patched wipes the object, baseline ${base_expect} as expected"
  else
    echo "FAIL ${b}: patched=${rc_fixed} control=${rc_base} (see ${fixed}, ${base})"
    status=1
  fi
done
exit "$status"
