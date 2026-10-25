#!/usr/bin/env python3
"""CVE-2019-11043 FastCGI regression; run against a specified Docker image."""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def record(kind, payload=b''):
    return struct.pack('!BBHHBB', 1, kind, 1, len(payload), 0, 0) + payload


def length(n):
    return bytes([n]) if n < 128 else struct.pack('!I', n | 0x80000000)


def request(path, extra):
    params = dict(SCRIPT_FILENAME='/test/worker.php', REQUEST_METHOD='GET',
                  SCRIPT_NAME='/worker.php', REQUEST_URI='/worker.php',
                  SERVER_PROTOCOL='HTTP/1.1', CONTENT_LENGTH='0', QUERY_STRING='')
    params.update(extra)
    encoded = b''
    for key, value in params.items():
        k, v = key.encode(), value.encode()
        encoded += length(len(k)) + length(len(v)) + k + v
    out, err, pending = b'', b'', b''
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(path)
        sock.sendall(record(1, struct.pack('!HB5x', 1, 0)) +
                     record(4, encoded) + record(4) + record(5))
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                raise RuntimeError('FastCGI closed without END_REQUEST')
            pending += chunk
            while len(pending) >= 8:
                version, kind, rid, size, pad, _ = struct.unpack('!BBHHBB', pending[:8])
                if version != 1 or rid != 1:
                    raise RuntimeError('Invalid FastCGI record')
                if len(pending) < 8 + size + pad:
                    break
                body, pending = pending[8:8+size], pending[8+size+pad:]
                if kind == 6:
                    out += body
                elif kind == 7:
                    err += body
                elif kind == 3:
                    if len(body) != 8 or struct.unpack('!IB3x', body) != (0, 0):
                        raise RuntimeError('Unsuccessful FastCGI completion')
                    headers, sep, content = out.partition(b'\r\n\r\n')
                    if not sep or b'Status:' in headers:
                        raise RuntimeError('Unexpected HTTP response: ' + repr(out))
                    return json.loads(content), err.decode(errors='replace')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', required=True)
    p.add_argument('--expect', choices=['fixed', 'vulnerable'], default='fixed')
    p.add_argument('--report', required=True)
    args = p.parse_args()
    cases = []
    report = dict(image=args.image, expectation=args.expect, cases=cases)
    with tempfile.TemporaryDirectory(prefix='fpm-path-info-') as directory:
        d = Path(directory)
        (d / 'worker.php').write_text('''<?php
header('Content-Type: application/json');
echo json_encode(array('marker' => 137 * 149, 'pid' => getmypid(),
 'path' => isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : null));
''')
        (d / 'fpm.conf').write_text('''[global]
error_log = /proc/self/fd/2
daemonize = no
[www]
user = root
group = root
listen = /test/fpm.sock
listen.mode = 0666
pm = static
pm.max_children = 1
pm.max_requests = 0
catch_workers_output = yes
php_admin_value[cgi.fix_pathinfo] = 1
''')
        container = subprocess.check_output([
            'docker', 'run', '-d', '--network', 'none', '--memory', '256m',
            '-v', directory + ':/test', args.image,
            'sapi/fpm/php-fpm', '-F', '-R', '-y', '/test/fpm.conf'], text=True).strip()
        try:
            report['image_id'] = subprocess.check_output(
                ['docker', 'inspect', '-f', '{{.Image}}', container], text=True).strip()
            path = str(d / 'fpm.sock')
            for _ in range(100):
                if Path(path).exists():
                    break
                time.sleep(.1)
            first, stderr = request(path, {})
            if first.get('marker') != 20413 or first.get('path') is not None or stderr:
                raise RuntimeError('Normal request preflight failed')
            pid = first['pid']
            # Upstream bug78599 reproducer plus a nonempty too-short PATH_INFO.
            for name, suffix, supplied, expected in [
                ('normal-path', '/hello', '/hello', '/hello'),
                ('empty-underflow', '/' + 'A' * 35, '', ''),
                ('short-underflow', '/' + 'A' * 35, '/x', '/x'),
            ]:
                try:
                    response, stderr = request(path, {
                        'SCRIPT_FILENAME': '/test/worker.php' + suffix,
                        'PATH_INFO': supplied, 'HTTP_HUI': 'PTEST' * 1000})
                    passed = (response.get('marker') == 20413 and
                              response.get('path') == expected and
                              response.get('pid') == pid and not stderr)
                    cases.append(dict(name=name, passed=passed, response=response, stderr=stderr))
                except (OSError, RuntimeError, ValueError) as exc:
                    cases.append(dict(name=name, passed=False, error=str(exc)))
            last, stderr = request(path, {})
            healthy = last.get('marker') == 20413 and last.get('pid') == pid and not stderr
            report['worker_healthy_and_reused'] = bool(healthy)
            fixed = all(c['passed'] for c in cases) and healthy
            # Infrastructure/preflight failure is never a successful negative control.
            negative = cases[0]['passed'] and any(not c['passed'] for c in cases[1:])
            report['passed'] = bool(fixed if args.expect == 'fixed' else negative)
        except Exception as exc:
            report.update(passed=False, error=str(exc))
        finally:
            logs = subprocess.run(['docker', 'logs', container], capture_output=True, text=True)
            report['logs'] = logs.stdout + logs.stderr
            subprocess.run(['docker', 'rm', '-f', container], capture_output=True, check=True)
    dest = Path(args.report)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
