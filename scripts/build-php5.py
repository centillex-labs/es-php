#!/usr/bin/env python3
"""Build locked PHP 5 security backports in Docker, never on the host."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('branch', choices=['5.4', '5.5', '5.6'])
parser.add_argument('--debug', action='store_true')
parser.add_argument('--jobs', type=int, default=3)
parser.add_argument('--variant', help='variant name; image tag suffix becomes this value')
parser.add_argument('--skip-patch', action='append', default=[],
                    help='series entry to omit (repeatable); builds an attribution variant')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
entry = json.loads((root / 'sources.lock.json').read_text())['branches'][args.branch]
archive = root / 'downloads' / ('php-' + entry['version'] + '.tar.gz')
if hashlib.sha256(archive.read_bytes()).hexdigest() != entry['sha256']:
    raise SystemExit('Source checksum mismatch')
series = [s.strip() for s in (root / f'php-{args.branch}-patches/series').read_text().splitlines()
          if s.strip() and not s.startswith('#')]
expected = [f'php-{args.branch}-patches/' + s for s in series]
if not expected or sorted(expected) != sorted(p['path'] for p in entry['patches']):
    raise SystemExit('Patch series does not match lock file')
for skipped in args.skip_patch:
    if skipped not in series:
        raise SystemExit('skip target is not in the series: ' + skipped)
for patch in entry['patches']:
    if hashlib.sha256((root / patch['path']).read_bytes()).hexdigest() != patch['sha256']:
        raise SystemExit('Patch checksum mismatch: ' + patch['path'])
series = [s for s in series if s not in args.skip_patch]
suffix = args.variant or ('debug' if args.debug else 'test')
if args.variant and args.debug:
    raise SystemExit('--variant cannot be combined with --debug')
log = root / f'work/reports/php-{args.branch}-{suffix}-build.log'
log.parent.mkdir(parents=True, exist_ok=True)
command = ['docker', 'build', '-f', 'containers/php-5/Dockerfile',
           '--build-arg', 'BRANCH=' + args.branch,
           '--build-arg', 'VERSION=' + entry['version'],
           '--build-arg', 'SHA256=' + entry['sha256'],
           '--build-arg', 'JOBS=' + str(args.jobs),
           '--build-arg', 'DEBUG=' + str(int(args.debug)),
           '--build-arg', 'VARIANT=' + suffix,
           '--build-arg', 'SKIP_PATCHES=' + ','.join(args.skip_patch),
           '-t', f'es-php:{args.branch}-{suffix}', '.']
with log.open('w') as stream:
    result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT)
print(json.dumps({'branch': args.branch, 'exit': result.returncode, 'log': str(log)}))
raise SystemExit(result.returncode)
