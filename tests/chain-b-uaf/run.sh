#!/usr/bin/env bash
# Chain B: var_destroy() reentrancy UAF, checked with Valgrind.
#
# Why Valgrind and not ASan: PHP's configure runs ASan-instrumented conftest
# binaries, and LeakSanitizer's exit-time scan hangs under the build sandbox --
# the build never finishes (observed: a conftest spinning at 100% CPU for
# minutes). Valgrind needs no rebuild and detects the same invalid read.
#
# The control image is important: it proves the trigger actually works. 8.1
# shows the UAF, 5.4 does not.
#
# Usage: run.sh [image:label ...]   (default: 5.4 and 8.1)
set -euo pipefail
cd "$(dirname "$0")"

TARGETS=("${@:-}")
[ -z "${TARGETS[0]:-}" ] && TARGETS=("es-php:5.4-debug:5.4" "es-php:8.1-serializer-debug:8.1-control")

for target in "${TARGETS[@]}"; do
  image="${target%%:*}:$(echo "${target#*:}" | cut -d: -f1)"
  image="${target%:*}"
  label="${target##*:}"
  echo "=== $label ($image)"
  docker run --rm --memory 1g -v "$PWD:/trigger:ro" "$image" \
    sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq valgrind >/dev/null 2>&1
           cd /usr/src/php
           USE_ZEND_ALLOC=0 valgrind --num-callers=12 sapi/cli/php /trigger/trigger_uaf.php 2>&1' \
    2>&1 | grep -E 'Invalid read|Invalid write|ERROR SUMMARY|__destruct fired|R:1500|var_access|var_destroy' \
         | sed 's/^/    /'
done
echo
echo "expected: the 8.1 control reports 'Invalid read of size 8' at var_access;"
echo "          5.4 reports 0 errors -- its var_destroy frees the reference chain"
echo "          and the deferred-destruction chain separately, and the reentrant"
echo "          unserialize() gets a fresh local var_hash."
