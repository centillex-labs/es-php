#!/usr/bin/env bash
# A/B the blog lab: patched LTS image vs unpatched baseline.
# Runs one container at a time (~3 MiB RSS each).
set -euo pipefail
cd "$(dirname "$0")"

: "${BLOG_PASSWORD:?export BLOG_PASSWORD=... (disposable lab password)}"

PATCHED_IMAGE="${PATCHED_IMAGE:-es-php:5.4-test}"
BASELINE_IMAGE="${BASELINE_IMAGE:-es-php:5.4-baseline}"
export BLOG_PORT="${BLOG_PORT:-8054}"
export BLOG_LAB_ENABLED=1

for image in "$PATCHED_IMAGE" "$BASELINE_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "missing image: $image" >&2
    echo "  patched : python3 scripts/build-php5.py 5.4" >&2
    echo "  baseline: docker build -f containers/php-5/Dockerfile.baseline \\" >&2
    echo "              -t es-php:5.4-baseline --build-arg VERSION=5.4.45 \\" >&2
    echo "              --build-arg SHA256=\$(python3 -c \"import json;print(json.load(open('sources.lock.json'))['branches']['5.4']['sha256'])\") ." >&2
    exit 2
  }
done

teardown() { docker compose down -v >/dev/null 2>&1 || true; }
trap teardown EXIT

run_case() {
  local label="$1" image="$2" expect="$3" rc=0
  echo "=== $label ($image)"
  BLOG_IMAGE="$image" docker compose up -d --force-recreate >/dev/null
  for _ in $(seq 1 40); do
    curl -fsS "http://127.0.0.1:${BLOG_PORT}/?action=health" >/dev/null 2>&1 && break
    sleep 0.5
  done
  python3 smoke.py --url "http://127.0.0.1:${BLOG_PORT}" --lab || rc=$?
  teardown
  if [ "$rc" -eq "$expect" ]; then
    echo "  -> as expected (exit $rc)"
    return 0
  fi
  echo "  -> UNEXPECTED: exit $rc, wanted $expect" >&2
  return 1
}

status=0
run_case "patched LTS"        "$PATCHED_IMAGE"  0 || status=1
run_case "unpatched baseline" "$BASELINE_IMAGE" 2 || status=1
if [ "$status" -eq 0 ]; then echo "A/B OK"; else echo "A/B FAILED" >&2; fi
exit "$status"
