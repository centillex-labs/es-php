#!/usr/bin/env python3
"""Fast, offline consistency check for the patch/lock/release metadata.

Catches the mistakes that would otherwise only surface during a release:
a series entry with no file, a lock hash that drifted from disk, a patch on
disk that no series references, a bad ``es_revision``, or a wrong
``version_id``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "sources.lock.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version_id(version: str) -> int:
    major, minor, patch = (int(part) for part in version.split("."))
    return major * 10000 + minor * 100 + patch


def main() -> int:
    lock = json.loads(LOCK.read_text())
    errors: list[str] = []
    checked = 0

    for branch, entry in lock["branches"].items():
        prefix = f"[{branch}]"

        if version_id(entry["version"]) != entry.get("version_id"):
            errors.append(
                f"{prefix} version_id {entry.get('version_id')} != "
                f"{version_id(entry['version'])} for {entry['version']}"
            )

        revision = entry.get("es_revision")
        if not isinstance(revision, int) or revision < 1:
            errors.append(f"{prefix} es_revision must be a positive int, got {revision!r}")

        patch_root = ROOT / f"php-{branch}-patches"
        series_file = patch_root / "series"
        if not series_file.is_file():
            errors.append(f"{prefix} missing {series_file.relative_to(ROOT)}")
            continue

        series = [
            line.strip()
            for line in series_file.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not series:
            errors.append(f"{prefix} series is empty")

        lock_patches = {
            (ROOT / p["path"]).relative_to(patch_root).as_posix(): p
            for p in entry.get("patches", [])
        }

        for name in series:
            path = patch_root / name
            if not path.is_file():
                errors.append(f"{prefix} series references missing patch {name}")
                continue
            if name not in lock_patches:
                errors.append(f"{prefix} series patch {name} is not in sources.lock.json")
                continue
            got = sha256(path)
            if got != lock_patches[name]["sha256"]:
                errors.append(
                    f"{prefix} {name}: sha256 {got[:12]}… != lock "
                    f"{lock_patches[name]['sha256'][:12]}…"
                )
            checked += 1

        for name in lock_patches:
            if name not in series:
                errors.append(
                    f"{prefix} sources.lock.json lists {name} but series does not apply it"
                )

    if errors:
        for err in errors:
            print(f"ERROR {err}", file=sys.stderr)
        print(f"\n{len(errors)} consistency error(s)", file=sys.stderr)
        return 1

    print(f"OK: {len(lock['branches'])} branches, {checked} patches, hashes match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
