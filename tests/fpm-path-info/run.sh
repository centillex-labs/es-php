#!/usr/bin/env bash
# CVE-2019-11043 regression: patched image must be correct, unpatched control
# must be observably wrong. Both outcomes are required for the test to pass.
set -uo pipefail
cd "$(dirname "$0")/../.."
branches=("$@")
[ ${#branches[@]} -eq 0 ] && branches=(5.4 5.5 5.6)
status=0
for b in "${branches[@]}"; do
  fixed="work/reports/php-${b}-fpm-path-info-fixed.json"
  base="work/reports/php-${b}-fpm-path-info-baseline.json"
  python3 tests/fpm-path-info/run.py --image "es-php:${b}-test" \
    --expect fixed --report "$fixed" >/dev/null
  rc_fixed=$?
  python3 tests/fpm-path-info/run.py --image "es-php:${b}-baseline" \
    --expect vulnerable --report "$base" >/dev/null
  rc_base=$?
  if [ "$rc_fixed" -eq 0 ] && [ "$rc_base" -eq 0 ]; then
    echo "OK   ${b}: patched correct, unpatched baseline still shows the fault"
  else
    echo "FAIL ${b}: patched=${rc_fixed} control=${rc_base} (see ${fixed}, ${base})"
    status=1
  fi
done
exit "$status"
