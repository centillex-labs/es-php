#!/usr/bin/env bash
# Upload-progress encoding scope: what patch 003 changes, and what it must not.
#
# The point of this test is the boundary, not the encoding. It asserts that the
# progress record inside $_SESSION is encoded while $_FILES is left completely
# alone, and that '>' is deliberately NOT encoded (no PHP tag opens with '>').
#
# It runs against patched and unpatched images, because a scope test that passes
# on both builds would prove nothing about the patch.
#
# Usage: run.sh [branch]        (default 5.4)
set -euo pipefail
cd "$(dirname "$0")"

BRANCH="${1:-${BRANCH:-5.4}}"
PATCHED_IMAGE="${PATCHED_IMAGE:-es-php:${BRANCH}-test}"
BASELINE_IMAGE="${BASELINE_IMAGE:-es-php:${BRANCH}-baseline}"
PORT="${SCOPE_PORT:-8060}"
NAME=scope-lab

for image in "$PATCHED_IMAGE" "$BASELINE_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "missing image: $image" >&2
    echo "  build with scripts/build-php5.py ${BRANCH} and containers/php-5/Dockerfile.baseline" >&2
    exit 2
  }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
mkdir -p "$WORK/sess"
cp -r web/. "$WORK/"
chmod -R 777 "$WORK/sess"

run_case() {
  local mode="$1" image="$2"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  # Wipe the session dir: the two modes share it, and a leftover file from the
  # patched run would make the baseline read already-encoded data and pass.
  rm -rf "$WORK/sess"; mkdir -p "$WORK/sess"; chmod 777 "$WORK/sess"
  # The CLI server is enough here: this tests the session write path, which is
  # SAPI-independent, so no Apache/CGI indirection is needed.
  docker run -d --name "$NAME" --user 0:0 -v "$WORK:/scope" -w /usr/src/php \
    -p "127.0.0.1:${PORT}:8080" "$image" \
    sapi/cli/php -c /scope/php.ini -S 0.0.0.0:8080 -t /scope >/dev/null
  for _ in $(seq 1 40); do
    curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/index.php" >/dev/null 2>&1 && break
    sleep 0.5
  done
  echo "=== $mode ($image)"
  python3 check.py "http://127.0.0.1:${PORT}" "$NAME" "$mode" | sed 's/^/    /'
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}

status=0
run_case patched  "$PATCHED_IMAGE"  || status=1
run_case baseline "$BASELINE_IMAGE" || status=1

if [ "$status" -eq 0 ]; then
  echo "scope OK: encoded in the progress record, raw everywhere else"
else
  echo "scope MISMATCH" >&2
fi
exit "$status"
