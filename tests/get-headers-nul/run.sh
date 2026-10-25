#!/usr/bin/env bash
# CVE-2020-7066 regression: patched builds refuse a URL containing NUL, the
# unpatched baseline still truncates the request line at the NUL.
set -uo pipefail
cd "$(dirname "$0")/../.."
branches=("$@")
[ ${#branches[@]} -eq 0 ] && branches=(5.4 5.5 5.6)
status=0
for b in "${branches[@]}"; do
  fixed="work/reports/php-${b}-get-headers-fixed.json"
  base="work/reports/php-${b}-get-headers-baseline.json"
  python3 tests/get-headers-nul/run.py --image "es-php:${b}-test" \
    --expect fixed --report "$fixed" >/dev/null
  rc_fixed=$?
  python3 tests/get-headers-nul/run.py --image "es-php:${b}-baseline" \
    --expect vulnerable --report "$base" >/dev/null
  rc_base=$?
  if [ "$rc_fixed" -eq 0 ] && [ "$rc_base" -eq 0 ]; then
    echo "OK   ${b}: patched refuses NUL, baseline truncates the request"
  else
    echo "FAIL ${b}: patched=${rc_fixed} control=${rc_base} (see ${fixed}, ${base})"
    status=1
  fi
done
exit "$status"
