#!/usr/bin/env bash
# A/B the CVE-2026-109618 OOM against Apache mod_php -- the SAPI the advisory
# actually describes. The RCE conversion depends on mod_php's request shutdown
# running on invalid memory after an OOM, so this is the closest we can get to
# the real target without attempting the heap-shaping conversion.
#
# Runs one container at a time (~40 MiB RSS plus Apache workers).
set -euo pipefail
cd "$(dirname "$0")"

PATCHED_IMAGE="${PATCHED_IMAGE:-es-php:5.4-modphp}"
BASELINE_IMAGE="${BASELINE_IMAGE:-es-php:5.4-modphp-baseline}"
PORT="${MODPHP_PORT:-8057}"
NAME=modphp-lab

for image in "$PATCHED_IMAGE" "$BASELINE_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "missing image: $image" >&2
    echo "  build with:" >&2
    echo "    docker build -f containers/php-5/Dockerfile.modphp -t $PATCHED_IMAGE \\" >&2
    echo "      --build-arg BRANCH=5.4 --build-arg VERSION=5.4.45 \\" >&2
    echo "      --build-arg SHA256=\$(python3 -c \"import json;print(json.load(open('sources.lock.json'))['branches']['5.4']['sha256'])\") ." >&2
    echo "    # add --build-arg SKIP_PATCHES=1 and -t $BASELINE_IMAGE for the baseline" >&2
    exit 2
  }
done

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

run_case() {
  local label="$1" image="$2"
  cleanup
  docker run -d --name "$NAME" --user 0:0 \
    -e PHP_MEMORY_LIMIT=8M -e PHP_POST_MAX_SIZE=64M \
    -v "$PWD/web:/web:ro" \
    --tmpfs /data:rw,noexec,nosuid,size=16m,mode=1777 \
    --tmpfs /tmp:rw,noexec,nosuid,size=8m \
    --memory 256m -p "127.0.0.1:${PORT}:8080" "$image" >/dev/null
  for _ in $(seq 1 60); do
    curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/?action=health" >/dev/null 2>&1 && break
    sleep 0.5
  done
  echo "--- $label ($image)"
  echo "    before: $(curl -s --max-time 5 "http://127.0.0.1:${PORT}/?action=health")"
  python3 oom_probe.py --url "http://127.0.0.1:${PORT}" 2>&1 | sed 's/^/    /'
  echo "    after : $(curl -s --max-time 5 "http://127.0.0.1:${PORT}/?action=health")"
  docker logs "$NAME" 2>&1 | grep -iE 'memory size|multipart' | tail -2 | sed 's/^/    log: /' || true
  cleanup
}

run_case "BASELINE unpatched mod_php" "$BASELINE_IMAGE"
echo
run_case "PATCHED mod_php" "$PATCHED_IMAGE"
echo
echo "expected: baseline returns HTTP 500 (request shutdown ran on the OOM path);"
echo "          patched drops the connection (worker exits before shutdown)."
echo "          Both keep serving -- Apache replaces the worker either way."
