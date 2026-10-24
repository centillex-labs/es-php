#!/usr/bin/env python3
"""No-WAF PHP2Shell trigger-shape probe against patched es-php Docker images.

Adapted from ../block-phpshell/tests/prod_check.py: the same benign probe
requests (no exploit payloads), but run directly against each patched PHP
runtime with no proxy/WAF in the path.

Unlike prod_check.py, nothing is expected to be blocked. The property under
test is: each benign trigger-shaped request returns valid fixture JSON from
the expected version and the same worker PID, which keeps serving afterwards.
This exercises worker reuse but does not reproduce CVE-2026-109619 or establish
absence of memory corruption.

Limitations: the CLI built-in server is a smoke-test SAPI, not mod_php/FPM
request handling; chunked upload framing (prod_check --size) is not covered.
"""
import http.client
import hashlib
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
import uuid

ROOT = Path(__file__).resolve().parents[2]

IMAGES = [
    ('8.1', 'es-php:8.1-test', 18091),
    ('7.4', 'es-php:7.4-test', 18092),
    ('7.3', 'es-php:7.3-test', 18093),
    ('7.2', 'es-php:7.2-test', 18094),
    ('7.1', 'es-php:7.1-test', 18095),
    ('7.0', 'es-php:7.0-test', 18096),
    ('5.6', 'es-php:5.6-test', 18097),
    ('5.5', 'es-php:5.5-test', 18098),
    ('5.4', 'es-php:5.4-test', 18099),
]


def send(port, method='GET', body=None, headers=None, query=''):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
    path = '/index.php' + (f'?{query}' if query else '')
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read(65536)
    except (OSError, http.client.HTTPException):
        return None, b''
    finally:
        conn.close()


def multipart(*parts):
    body = ''.join(f'--XyZ\r\n{p}\r\n' for p in parts) + '--XyZ--\r\n'
    return body.encode(), {'Content-Type': 'multipart/form-data; boundary=XyZ'}


def field(name):
    return f'Content-Disposition: form-data; name="{name}"\r\n\r\nv'


def probes():
    form = {'Content-Type': 'application/x-www-form-urlencoded'}
    return [
        ('serialized PHP in form value (Chain B grammar)',
         dict(method='POST', body=b'd=O:4:%22Evil%22:1:{s:3:%22cmd%22;s:2:%22id%22;}', headers=form)),
        ('session upload-progress field (CVE-2026-109619)',
         dict(method='POST', **dict(zip(('body', 'headers'), multipart(field('PHP_SESSION_UPLOAD_PROGRESS')))))),
        ('excess headers in one multipart part',
         dict(method='POST', **dict(zip(('body', 'headers'), multipart('X-Pad: 1\r\n' * 9 + field('a')))))),
        ('excess empty file controls',
         dict(method='POST', **dict(zip(('body', 'headers'), multipart(
             *['Content-Disposition: form-data; name="f[]"; filename=""\r\n'] * 21))))),
        ('long multipart filename',
         dict(method='POST', **dict(zip(('body', 'headers'), multipart(
             'Content-Disposition: form-data; name="f"; filename="' + 'a' * 2000 + '"\r\n\r\nx'))))),
        ('deep field-name nesting', dict(query='a' + '[x]' * 9 + '=1')),
        ('long form field name',
         dict(method='POST', body=b'a' * 4096 + b'=1', headers=form)),
        ('raw control bytes in form body',
         dict(method='POST', body=b'a=1&=\x00\x01', headers=form)),
    ]


def fixture(body):
    try:
        value = json.loads(body)
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def healthy(status, body, expected_version, expected_pid=None):
    data = fixture(body)
    return (status == 200 and data.get('php_version') == expected_version
            and data.get('sapi') == 'cli-server'
            and isinstance(data.get('pid'), int) and data['pid'] > 0
            and (expected_pid is None or data['pid'] == expected_pid))


def run_version(version, image, port):
    container_name = f'es-php-lab-{version}-{uuid.uuid4().hex[:8]}'
    expected_version = json.loads((ROOT / 'sources.lock.json').read_text())['branches'][version]['version']
    report = {'version': version, 'image': image, 'expected_version': expected_version,
              'started': False, 'passed': False, 'results': []}
    proc = subprocess.run(
        ['docker', 'run', '-d', '--name', container_name,
         '--memory', '256m', '--pids-limit', '128',
         '-v', f'{ROOT}/tests/php-lab/web:/web:ro',
         '-p', '127.0.0.1::80',
         image, 'sapi/cli/php', '-n', '-d', 'display_errors=0', '-d', 'log_errors=1',
         '-d', 'memory_limit=128M', '-S', '0.0.0.0:80', '-t', '/web'],
        capture_output=True, text=True)
    if proc.returncode:
        report['error'] = proc.stderr.strip()
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)
        return report
    report['started'] = True
    report['image_id'] = subprocess.check_output(
        ['docker', 'inspect', '-f', '{{.Image}}', container_name], text=True).strip()
    try:
        # Docker allocates a free loopback port; don't collide with other labs.
        binding = subprocess.check_output(['docker', 'port', container_name, '80/tcp'], text=True).strip()
        port = int(binding.rsplit(':', 1)[1])
        report['url'] = f'http://127.0.0.1:{port}/index.php'
        for _ in range(200):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError('server never became ready')

        # Run the user's original script unchanged as well. Exit 1 is expected
        # without Aegis: its assertions require WAF-specific rejection markers.
        original = ROOT.parent / 'block-phpshell/tests/prod_check.py'
        if original.exists():
            raw = subprocess.run([sys.executable, str(original),
                                  f'http://127.0.0.1:{port}/index.php'],
                                 capture_output=True, text=True, timeout=300)
            raw_log = ROOT / f'work/reports/php-lab-{version}-prod-check.log'
            raw_log.parent.mkdir(parents=True, exist_ok=True)
            raw_log.write_text(raw.stdout + raw.stderr)
            report['original_waf_check'] = {
                'path': str(original), 'sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
                'exit_code': raw.returncode, 'log': str(raw_log),
                'note': 'WAF assertions are expected to fail without WAF; not a CVE verdict'}
        results = report['results']
        status, body = send(port)
        first_pid = fixture(body).get('pid')
        entry = {'name': 'baseline GET', 'status': status, 'pid': first_pid,
                 'passed': healthy(status, body, expected_version)}
        results.append(entry)
        if not entry['passed']:
            report['error'] = body.decode(errors='replace')[:1000]
            return report

        # /fatal deliberately returns HTTP 500; it is NOT a PHP fatal error.
        fatal_status, _ = send_path(port, '/index.php/fatal')
        session_status, session_body = send_path(port, '/index.php/session')
        results.append({'name': 'explicit HTTP 500 before probes', 'status': fatal_status,
                        'passed': fatal_status == 500})
        results.append({'name': 'session start before probes', 'status': session_status,
                        'pid': fixture(session_body).get('pid'),
                        'passed': healthy(session_status, session_body, expected_version, first_pid)})

        for name, kwargs in probes():
            status, body = send(port, **kwargs)
            data = fixture(body)
            passed = healthy(status, body, expected_version, first_pid)
            results.append({'name': name, 'status': status, 'pid': data.get('pid'),
                            'post_keys': data.get('post_keys'), 'file_keys': data.get('file_keys'),
                            'passed': passed})

        # Same-worker follow-up: session and normal requests must still work.
        follow_status, follow_body = send_path(port, '/index.php/session')
        final_status, final_body = send(port)
        results.append({'name': 'session after probes', 'status': follow_status,
                        'pid': fixture(follow_body).get('pid'),
                        'passed': healthy(follow_status, follow_body, expected_version, first_pid)})
        results.append({'name': 'final GET', 'status': final_status,
                        'passed': healthy(final_status, final_body, expected_version, first_pid),
                        'pid': fixture(final_body).get('pid')})

        report['same_worker'] = all(r.get('pid') == first_pid for r in results
                                    if r['name'] != 'explicit HTTP 500 before probes')
        report['passed'] = all(r['passed'] for r in results) and report['same_worker']
        return report
    except Exception as exc:
        report['error'] = str(exc)
        return report
    finally:
        logs = subprocess.run(['docker', 'logs', container_name], capture_output=True, text=True)
        log_path = ROOT / f'work/reports/php-lab-{version}.log'
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(logs.stdout + logs.stderr)
        report['container_log'] = str(log_path)
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)


def send_path(port, path):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
    try:
        conn.request('GET', path)
        response = conn.getresponse()
        return response.status, response.read(65536)
    except (OSError, http.client.HTTPException):
        return None, b''
    finally:
        conn.close()


def main():
    selected = sys.argv[1:] or [v for v, _, _ in IMAGES]
    unknown = set(selected) - {v for v, _, _ in IMAGES}
    if unknown:
        sys.exit('Unknown versions: ' + ', '.join(sorted(unknown)))
    reports = []
    for version, image, port in IMAGES:
        if version not in selected:
            continue
        report = run_version(version, image, port)
        reports.append(report)
        print(json.dumps(report, indent=2))
    dest = ROOT / 'work/reports/php-lab-summary.json'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(reports, indent=2) + '\n')
    failed = [r['version'] for r in reports if not r.get('passed')]
    print(json.dumps({'passed': not failed, 'failed_versions': failed, 'report': str(dest)}))
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
