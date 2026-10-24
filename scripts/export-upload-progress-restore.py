#!/usr/bin/env python3
"""Generate compatibility overrides after the combined EOL mitigation.

This restores the upstream session callback, NOT a replacement security fix.
Original mitigation patches are retained unchanged for provenance.
"""
import difflib
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for branch in ['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.1']:
    after = (root / f'php-{branch}/ext/session/session.c').read_text()
    old = '\tif (!PS(rfc1867_enabled)) {'
    assert after.count(old) == 1
    constant = 'true' if branch in ['7.3', '7.4', '8.1'] else '1'
    disabled = f'\tif (!PS(rfc1867_enabled) || {constant}) {{'
    if branch.startswith('5.'):
        disabled = '\t/* EOL mitigation: progress decoding must not run during request startup. */\n' + disabled
    before = after.replace(old, disabled)
    patch = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                       fromfile='a/ext/session/session.c', tofile='b/ext/session/session.c'))
    path = root / f'php-{branch}-patches/CVE-2026-109619/002-restore-upload-progress.patch'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(patch)
    print(json.dumps({'branch': branch, 'path': str(path.relative_to(root)),
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))
