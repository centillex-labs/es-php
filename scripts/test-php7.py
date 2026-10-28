#!/usr/bin/env python3
"""Record PHP 5/7/8 Docker suite failures and OOM behavior without suppressing either.
Historical script name retained; PHP 5 branches share the same probe code.
"""
import argparse
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser()
p.add_argument('branch', choices=['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1'])
p.add_argument('--debug', action='store_true')
a = p.parse_args()
root = Path(__file__).resolve().parent.parent
suffix = 'debug' if a.debug else 'test'
image = 'es-php:' + a.branch + '-' + suffix
prefix = root / 'work/reports' / ('php-' + a.branch + '-' + suffix)
prefix.parent.mkdir(parents=True, exist_ok=True)
results = []
for name, code in [
    ('allocation-oom', '$x=str_repeat("x",64*1024*1024);'),
    ('unserialize-oom', '$s="a:200000:{".str_repeat("i:0;a:1:{i:0;i:1;}",200000)."}";$x=unserialize($s);'),
    ('concat-oom', '$x=str_repeat("x",10*1024*1024);$y=$x.$x;'),
]:
    script = 'register_shutdown_function(function(){echo "SHUTDOWN_RAN";});' + code + 'echo "CONTINUED";'
    r = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--memory', '256m', image,
                        'sapi/cli/php', '-n', '-d', 'memory_limit=16M', '-r', script],
                       capture_output=True, text=True, timeout=30)
    out = r.stdout + r.stderr
    results.append({'name': name, 'exit': r.returncode, 'output': out,
                    'passed': r.returncode == 1 and 'Allowed memory size' in out
                    and 'SHUTDOWN_RAN' not in out and 'CONTINUED' not in out})
for sapi in ['cli/php', 'fpm/php-fpm']:
    r = subprocess.run(['docker', 'run', '--rm', '--network', 'none', image, 'sapi/' + sapi, '-v'],
                       capture_output=True, text=True, timeout=30)
    results.append({'name': sapi, 'passed': r.returncode == 0, 'output': r.stdout + r.stderr})
log = Path(str(prefix) + '-suite.log')
with log.open('w') as stream:
    suite = subprocess.run(['docker', 'run', '--rm', '--network', 'none',
                            '-e', 'NO_INTERACTION=1', '-e', 'REPORT_EXIT_STATUS=1', image,
                            'sapi/cli/php', 'run-tests.php', '-q', '-p', '/usr/src/php/sapi/cli/php',
                            'ext/session/tests', 'ext/standard/tests/serialize'],
                           stdout=stream, stderr=subprocess.STDOUT, timeout=300)
report = {'branch': a.branch, 'image': image, 'probes': results, 'suite_exit': suite.returncode,
          'suite_log': str(log), 'probes_passed': all(r['passed'] for r in results)}
Path(str(prefix) + '-validation.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
raise SystemExit(0 if report['probes_passed'] and suite.returncode == 0 else 1)
