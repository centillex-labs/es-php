#!/usr/bin/env python3
"""CVE-2020-7066 / bug #79329: get_headers() must reject NUL bytes in the URL.

Upstream (PHP 7) changed the parameter from Z_PARAM_STRING to Z_PARAM_PATH. The
PHP 5 equivalent is the 'p' specifier: it applies the same NUL check
(CHECK_ZVAL_NULL_PATH) without touching the value. Verified in
Zend/zend_API.c: 'p' and 's' share one code path and differ only by that check.
"""
import difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = "0d139c5b94a5f485a66901919e51faddb0371c43"
REL = "ext/standard/url.c"
OLD = '\tif (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &url, &url_len, &format) == FAILURE) {\n'
NEW = '\tif (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "p|l", &url, &url_len, &format) == FAILURE) {\n'
HEADER = (
    "Subject: [PATCH] Fix bug #79329: get_headers() must not accept NUL in the URL\n"
    f"Upstream: https://github.com/php/php-src/commit/{UPSTREAM}\n"
    "CVE: CVE-2020-7066\n"
    "Port: Z_PARAM_STRING -> Z_PARAM_PATH becomes 's' -> 'p' for PHP 5\n\n"
)

for branch in ("5.4", "5.5", "5.6"):
    source = (ROOT / f"php-{branch}" / REL).read_text()
    start = source.index("PHP_FUNCTION(get_headers)")
    window = source[start:start + 2000]
    if window.count(OLD) != 1:
        raise SystemExit(f"{branch}: unexpected get_headers signature ({window.count(OLD)} matches)")
    # Replace only inside get_headers: find the global offset of that occurrence.
    offset = source.index(OLD, start)
    patched = source[:offset] + NEW + source[offset + len(OLD):]
    dest = ROOT / f"php-{branch}-patches/CVE-2020-7066/001-get-headers-reject-nul.patch"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(HEADER + "".join(difflib.unified_diff(
        source.splitlines(True), patched.splitlines(True),
        fromfile=f"a/{REL}", tofile=f"b/{REL}")))
    print(dest.relative_to(ROOT))
