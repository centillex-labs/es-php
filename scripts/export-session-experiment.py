#!/usr/bin/env python3
"""Export reviewed experimental files against the existing EOL-patched work tree."""
from pathlib import Path
import difflib
import re

root = Path(__file__).resolve().parent.parent
parts = re.split(r'(?=^diff --git )', (root / 'work/research/session-prerequisites.patch').read_text(), flags=re.M)
paths = [p.splitlines()[0].split()[2][2:] for p in parts if p.startswith('diff --git ')]
out = []
for name in paths:
    a = root / 'work/php-8.1' / name
    b = root / 'work/php-8.1-experimental' / name
    out.extend(difflib.unified_diff(
        a.read_text().splitlines(True) if a.exists() else [],
        b.read_text().splitlines(True),
        fromfile='a/' + name if a.exists() else '/dev/null', tofile='b/' + name))
(root / 'php-8.1-patches/CVE-2026-115560/001-experimental-session-prerequisites.patch').write_text(''.join(out))
