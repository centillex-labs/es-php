#!/usr/bin/env python3
"""Export reviewed scratch-tree changes; never export .rej/.orig or build outputs."""
import argparse
import difflib
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('branch', choices=['7.0', '7.1', '7.2', '7.3'])
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
upstream = root / 'php-7.4-patches/CVE-2026-109618/001-avoid-state-corruption.patch'
paths = {line.split()[2][2:] for line in upstream.read_text().splitlines() if line.startswith('diff --git ')}
paths.add('Zend/zend_string.h')
patch = []
for path in sorted(paths):
    old = root / ('php-' + args.branch) / path
    new = root / 'work' / ('php-' + args.branch) / path
    patch.extend(difflib.unified_diff(old.read_text().splitlines(True), new.read_text().splitlines(True),
                                    fromfile='a/' + path, tofile='b/' + path))
dest = root / ('php-' + args.branch + '-patches/CVE-2026-109618/001-avoid-state-corruption.patch')
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(''.join(patch))
print(dest)
