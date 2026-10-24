#!/usr/bin/env bash
# Compile a released tarball and assert the release actually carries the
# version suffix and the intended policy.  This is the check that makes the
# published artifact trustworthy: we build what we ship.
#
# Usage: verify-release-tarball.sh <tarball.tar.gz> [more.tar.gz ...]
set -euo pipefail

[ "$#" -ge 1 ] || { echo "usage: $0 <tarball.tar.gz> [...]" >&2; exit 2; }

for arg in "$@"; do
  tarball="$(cd "$(dirname "$arg")" && pwd)/$(basename "$arg")"
  echo "== verifying $(basename "$tarball")"

  # 1. sidecar checksum must match the file on disk
  ( cd "$(dirname "$tarball")" && sha256sum -c "$(basename "$tarball").sha256" )

  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  tar -xzf "$tarball" -C "$work"
  # Full listing to a file: piping into `head` would SIGPIPE tar under pipefail.
  tar tzf "$tarball" > "$work/.listing"
  top="$(head -1 "$work/.listing" | cut -d/ -f1)"
  src="$work/$top"
  [ -d "$src" ] || { echo "FAIL: $top/ not found in archive" >&2; exit 1; }
  cd "$src"

  # 2. manifest must describe the directory we just extracted
  read -r release vid extra < <(python3 - <<'PY'
import json
m = json.load(open("LTS-RELEASE.json"))
print(m["release"], m["php_version_id"], m["php_extra_version"])
PY
)
  [ "$top" = "php-$release" ] || { echo "FAIL: dir $top != php-$release" >&2; exit 1; }

  # 3. every shipped patch must match the manifest hash
  python3 - <<'PY'
import hashlib, json, sys
m = json.load(open("LTS-RELEASE.json"))
bad = []
for entry in m["patches"]:
    path = "lts-patches/" + entry["path"]
    got = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if got != entry["sha256"]:
        bad.append(f"{path}: {got} != {entry['sha256']}")
if bad:
    sys.exit("FAIL: shipped patch mismatch:\n" + "\n".join(bad))
print(f"    {len(m['patches'])} shipped patches match manifest")
PY

  # 4. configure with the flags the manifest records, then build
  mapfile -t flags < <(python3 -c \
    'import json;print("\n".join(json.load(open("LTS-RELEASE.json"))["configure_flags"]))')
  ./configure "${flags[@]}" >/dev/null
  make -j"$(nproc)" >/dev/null

  php=sapi/cli/php
  version_line="$("$php" -v 2>&1)"
  version_line="${version_line%%$'\n'*}"
  got="$("$php" -r 'echo PHP_VERSION;')"
  got_id="$("$php" -r 'echo PHP_VERSION_ID;')"
  got_extra="$("$php" -r 'echo PHP_EXTRA_VERSION;')"
  progress="$("$php" -r 'echo (int) ini_get("session.upload_progress.enabled");')"

  echo "    $version_line"
  echo "    PHP_VERSION=$got  PHP_EXTRA_VERSION=$got_extra  PHP_VERSION_ID=$got_id"
  echo "    session.upload_progress.enabled=$progress"

  [ "$got" = "$release" ] || { echo "FAIL: PHP_VERSION '$got' != '$release'" >&2; exit 1; }
  [ "$got_extra" = "$extra" ] || { echo "FAIL: PHP_EXTRA_VERSION '$got_extra' != '$extra'" >&2; exit 1; }
  [ "$got_id" = "$vid" ] || { echo "FAIL: PHP_VERSION_ID '$got_id' != '$vid'" >&2; exit 1; }
  case "$got_extra" in -lts*) ;; *) echo "FAIL: missing -lts suffix" >&2; exit 1;; esac
  [ "$progress" = "1" ] || { echo "FAIL: upload progress not enabled (policy regression)" >&2; exit 1; }

  echo "    OK"
done
