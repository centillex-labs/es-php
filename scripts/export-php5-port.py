#!/usr/bin/env python3
"""Export the reviewed PHP 5 scratch edits; never include build artifacts/rejects."""
import argparse
import difflib
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('branch', choices=['5.4', '5.5', '5.6'])
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
files = ['Zend/zend_alloc.c', 'Zend/zend_alloc.h', 'Zend/zend_execute_API.c',
         'Zend/zend_llist.c', 'Zend/zend_operators.c', 'Zend/zend_strtod.c', 'Zend/zend_hash.c',
         'main/main.c', 'main/SAPI.c', 'main/rfc1867.c', 'ext/session/session.c']
patch = ''.join(''.join(difflib.unified_diff(
    (root / f'php-{args.branch}' / name).read_text().splitlines(True),
    (root / f'work/php-{args.branch}' / name).read_text().splitlines(True),
    fromfile='a/' + name, tofile='b/' + name)) for name in files)
path = root / f'php-{args.branch}-patches/CVE-2026-109618/001-avoid-state-corruption.patch'
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(patch)
print(path)
