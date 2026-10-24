#!/usr/bin/env python3
"""Docker-only prerequisite tests; not proof of a CVE-2026-115560 fix."""
import json
import subprocess
from pathlib import Path

IMAGE = 'es-php:8.1-session-experimental'
ROOT = Path(__file__).resolve().parent.parent

def php(code):
    return subprocess.run(['docker', 'run', '--rm', '--network', 'none',
                           '--memory', '256m', IMAGE, 'sapi/cli/php', '-n',
                           '-d', 'memory_limit=16M', '-r', code],
                          capture_output=True, text=True, timeout=30)

results = []
for name, allocation in [
    ('allocation-oom', '$x = str_repeat("x", 64 * 1024 * 1024);'),
    ('unserialize-oom', '$s = "a:200000:{" . str_repeat("i:0;a:1:{i:0;i:1;}", 200000) . "}"; $x = unserialize($s);'),
]:
    result = php('register_shutdown_function(function () { echo "SHUTDOWN_RAN"; });' + allocation + 'echo "CONTINUED";')
    output = result.stdout + result.stderr
    passed = (result.returncode == 1 and 'Allowed memory size' in output
              and 'CONTINUED' not in output and 'SHUTDOWN_RAN' not in output)
    results.append({'name': name, 'passed': passed, 'exit': result.returncode, 'output': output})

for serializer in ['php', 'php_binary', 'php_serialize']:
    result = php('ini_set("session.serialize_handler", "' + serializer + '");'
                 'session_start(); $_SESSION = ["probe" => [1, "value", null]];'
                 '$data = session_encode(); $_SESSION = [];'
                 'if (!session_decode($data) || $_SESSION !== ["probe" => [1, "value", null]]) exit(2);'
                 'echo "ROUNDTRIP_OK";')
    results.append({'name': serializer + '-roundtrip',
                    'passed': result.returncode == 0 and result.stdout == 'ROUNDTRIP_OK',
                    'exit': result.returncode, 'output': result.stdout + result.stderr})

report = {'image': IMAGE, 'results': results, 'passed': all(r['passed'] for r in results)}
path = ROOT / 'work/reports/experimental-compatibility.json'
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
raise SystemExit(0 if report['passed'] else 1)
