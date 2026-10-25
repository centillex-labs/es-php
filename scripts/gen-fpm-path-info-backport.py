#!/usr/bin/env python3
"""Export the minimal CVE-2019-11043 fix; do not activate untested patches."""
from pathlib import Path
import difflib

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = "ab061f95ca966731b1c84cf5b7b20155c0a1c06a"
REL = "sapi/fpm/fpm/fpm_main.c"
OLD = """path_info = env_path_info ? env_path_info + pilen - slen : NULL;
								tflag = (orig_path_info != path_info);"""
NEW = """path_info = (env_path_info && pilen > slen) ? env_path_info + pilen - slen : NULL;
								tflag = path_info && (orig_path_info != path_info);"""

for branch in ("5.4", "5.5", "5.6"):
    source = (ROOT / f"php-{branch}" / REL).read_text()
    if source.count(OLD) != 1:
        raise SystemExit(f"{branch}: expected exactly one vulnerable block")
    fixed = source.replace(OLD, NEW)
    patch = "".join(difflib.unified_diff(
        source.splitlines(True), fixed.splitlines(True),
        fromfile=f"a/{REL}", tofile=f"b/{REL}"))
    dest = ROOT / f"php-{branch}-patches/CVE-2019-11043/001-bound-path-info.patch"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        "Subject: [PATCH] FPM: bound PATH_INFO suffix adjustment\n"
        f"Upstream: https://github.com/php/php-src/commit/{UPSTREAM}\n"
        "CVE: CVE-2019-11043\n"
        "Status: candidate; not yet enabled in the release series\n\n" + patch)
    print(dest.relative_to(ROOT))
