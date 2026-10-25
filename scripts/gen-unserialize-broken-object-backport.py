#!/usr/bin/env python3
"""CVE-2016-7124 / bug #72663: wipe a partially constructed object.

PHP 5.6 already carries the upstream fix (verified: the broken object comes back
as NULL). Only 5.4 and 5.5 leave it reachable, so only those two are patched.
Both the .re source and the shipped generated parser are patched, because the
builds keep shipped parser sources instead of regenerating them.
"""
import difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = "448c9be157f4147e121f1a2a524536c75c9c6059"
OLD = """\tif (!process_nested_data(UNSERIALIZE_PASSTHRU, Z_OBJPROP_PP(rval), elements, 1)) {
\t\treturn 0;
\t}
"""
NEW = """\tif (!process_nested_data(UNSERIALIZE_PASSTHRU, Z_OBJPROP_PP(rval), elements, 1)) {
\t\t/* We've got partially constructed object on our hands here. Wipe it. */
\t\tzend_hash_clean(Z_OBJPROP_PP(rval));
\t\tZVAL_NULL(*rval);
\t\treturn 0;
\t}
"""
HEADER = (
    "Subject: [PATCH] Fix bug #72663: destroy a partially unserialized object\n"
    f"Upstream: https://github.com/php/php-src/commit/{UPSTREAM}\n"
    "CVE: CVE-2016-7124\n"
    "Branches: 5.4, 5.5 (5.6 already carries this fix)\n\n"
)

for branch in ("5.4", "5.5"):
    chunks = []
    for name in ("var_unserializer.re", "var_unserializer.c"):
        rel = f"ext/standard/{name}"
        original = (ROOT / f"php-{branch}" / rel).read_text()
        if original.count(OLD) != 1:
            raise SystemExit(f"{branch}/{rel}: expected one match, got {original.count(OLD)}")
        chunks.append("".join(difflib.unified_diff(
            original.splitlines(True),
            original.replace(OLD, NEW).splitlines(True),
            fromfile=f"a/{rel}", tofile=f"b/{rel}")))
    dest = ROOT / f"php-{branch}-patches/CVE-2016-7124/001-destroy-broken-object.patch"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(HEADER + "".join(chunks))
    print(dest.relative_to(ROOT))
