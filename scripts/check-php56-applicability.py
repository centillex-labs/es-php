#!/usr/bin/env python3
"""Verify every citation in security/php56-vector-applicability.yaml.

Extracts the pristine baseline tarball to work/baseline-src (read-only use) and
checks that each cited token still appears on the cited line (+-3). This is a
reachability check of the documentation against the source, not a runtime test.
"""
import hashlib
import json
import sys
import tarfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / 'security/php56-vector-applicability.yaml'
WORK = ROOT / 'work' / 'baseline-src'
TOLERANCE = 3


def baseline_root(entry):
    marker = WORK / '.version'
    if marker.exists() and marker.read_text().strip() == entry['version']:
        return WORK / f"php-{entry['version']}"
    WORK.mkdir(parents=True, exist_ok=True)
    archive = ROOT / 'downloads' / f"php-{entry['version']}.tar.gz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != entry['sha256']:
        raise SystemExit('baseline checksum mismatch')
    with tarfile.open(archive) as tar:
        tar.extractall(WORK, filter='data')
    marker.write_text(entry['version'] + '\n')
    return WORK / f"php-{entry['version']}"


def main():
    data = yaml.safe_load(MAP.read_text())
    entry = json.loads((ROOT / 'sources.lock.json').read_text())['branches']['5.6']
    root = baseline_root(entry)
    failures = []
    counts = {}
    for vector in data['vectors']:
        counts[vector['applicability']] = counts.get(vector['applicability'], 0) + 1
        if not vector.get('citations'):
            failures.append((vector['id'], 'no citations'))
            continue
        for cite in vector['citations']:
            path = root / cite['file']
            token = cite['token']
            if not path.is_file():
                failures.append((vector['id'], f"missing file {cite['file']}"))
                continue
            lines = path.read_text(errors='replace').splitlines()
            lo = max(0, cite['line'] - 1 - TOLERANCE)
            hi = min(len(lines), cite['line'] + TOLERANCE)
            window = lines[lo:hi]
            if not any(token in line for line in window):
                failures.append((vector['id'], f"{cite['file']}:{cite['line']} missing token {token!r}"))
        print(f"{vector['id']:3} {vector['applicability']:14} {len(vector['citations'])} citation(s)  {vector['mechanism']}")
    print('summary:', ', '.join(f'{k}={v}' for k, v in sorted(counts.items())))
    if failures:
        for vid, why in failures:
            print(f'FAIL {vid}: {why}', file=sys.stderr)
        raise SystemExit(1)
    print(f'OK: {len(data["vectors"])} vectors, all citations match php-{entry["version"]}')


if __name__ == '__main__':
    main()
