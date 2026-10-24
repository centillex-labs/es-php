#!/usr/bin/env python3
"""Build a branch-specific PHP 5/7/8.1 backport inside Docker using locked sources."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('branch', choices=['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.1'])
parser.add_argument('--debug', action='store_true')
parser.add_argument('--jobs', type=int, default=4)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
entry = json.loads((root / 'sources.lock.json').read_text())['branches'][args.branch]
archive = root / 'downloads' / ('php-' + entry['version'] + '.tar.xz')
assert hashlib.sha256(archive.read_bytes()).hexdigest() == entry['sha256'], 'Source checksum mismatch'
series = [s.strip() for s in (root / f'php-{args.branch}-patches/series').read_text().splitlines()
          if s.strip() and not s.startswith('#')]
expected = [f'php-{args.branch}-patches/' + s for s in series]
assert expected and expected == [p['path'] for p in entry['patches']], 'Series does not match lock file'
for patch in entry['patches']:
    assert hashlib.sha256((root / patch['path']).read_bytes()).hexdigest() == patch['sha256'], 'Patch checksum mismatch'
suffix = 'debug' if args.debug else 'test'
log = root / 'work/reports' / ('php-' + args.branch + '-' + suffix + '-build.log')
log.parent.mkdir(parents=True, exist_ok=True)
command = ['docker', 'build', '-f', 'containers/php-7/Dockerfile',
           '--build-arg', 'BRANCH=' + args.branch,
           '--build-arg', 'VERSION=' + entry['version'],
           '--build-arg', 'SHA256=' + entry['sha256'],
           '--build-arg', 'JOBS=' + str(args.jobs),
           '--build-arg', 'DEBUG=' + str(int(args.debug)),
           '-t', 'es-php:' + args.branch + '-' + suffix, '.']
with log.open('w') as stream:
    result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT)
print(json.dumps({'branch': args.branch, 'exit': result.returncode, 'log': str(log)}))
raise SystemExit(result.returncode)
