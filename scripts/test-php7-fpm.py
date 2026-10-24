#!/usr/bin/env python3
"""Isolated single-worker FPM smoke test: reuse, handler cleanup, OOM replacement.
Supports PHP 5 and 7. Not an exploit reproduction or comprehensive CVE verification.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument('branch', choices=['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.1'])
a = p.parse_args()
image = 'es-php:' + a.branch + '-test'
root = Path(__file__).resolve().parent.parent

def record(kind, payload=b''):
    return struct.pack('!BBHHBB', 1, kind, 1, len(payload), 0, 0) + payload

def length(n):
    return bytes([n]) if n < 128 else struct.pack('!I', n | 0x80000000)

def request(path, query):
    params = {'SCRIPT_FILENAME':'/test/worker.php', 'REQUEST_METHOD':'GET',
              'QUERY_STRING':query, 'SERVER_PROTOCOL':'HTTP/1.1', 'CONTENT_LENGTH':'0'}
    encoded = b''
    for k, v in params.items():
        k, v = k.encode(), v.encode()
        encoded += length(len(k)) + length(len(v)) + k + v
    output = b''
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(path)
        s.sendall(record(1, struct.pack('!HB5x', 1, 0)) + record(4, encoded) + record(4) + record(5))
        data = b''
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            while len(data) >= 8:
                _, kind, _, size, padding, _ = struct.unpack('!BBHHBB', data[:8])
                if len(data) < 8 + size + padding:
                    break
                body, data = data[8:8+size], data[8+size+padding:]
                if kind in (6, 7):
                    output += body
                if kind == 3:
                    return output.decode(errors='replace')
    return output.decode(errors='replace')

def pid(output):
    import re
    match = re.search(r'WORKER=(\d+)', output)
    if not match:
        raise RuntimeError('Missing worker response: ' + output)
    return int(match[1])

with tempfile.TemporaryDirectory(prefix='php7-fpm-') as directory:
    d = Path(directory)
    # Container workers run as root only inside this isolated test container.
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
php_admin_value[memory_limit] = 16M
php_admin_flag[display_errors] = on
''')
    (d / 'worker.php').write_text('''<?php
$action = isset($_GET['action']) ? $_GET['action'] : 'check';
if ($action === 'install') {
    set_error_handler(function () { echo "STALE_HANDLER"; });
    set_exception_handler(function ($e) { echo "STALE_EXCEPTION"; });
} elseif ($action === 'oom') {
    register_shutdown_function(function () { echo "SHUTDOWN_RAN"; });
    $x = str_repeat("x", 64 * 1024 * 1024);
    echo "CONTINUED";
} else {
    trigger_error("CURRENT_REQUEST_WARNING", E_USER_WARNING);
}
echo "WORKER=" . getmypid();
''')
    run = subprocess.run(['docker','run','-d','--network','none','--memory','256m',
                          '-v', directory + ':/test', image,
                          'sapi/fpm/php-fpm','-F','-R','-y','/test/fpm.conf'],
                         capture_output=True, text=True, check=True)
    container = run.stdout.strip()
    try:
        path = str(d / 'fpm.sock')
        for _ in range(100):
            if Path(path).exists():
                break
            time.sleep(.1)
        first = request(path, 'action=install')
        second = request(path, 'action=check')
        reused = pid(first) == pid(second)
        try:
            oom = request(path, 'action=oom')
        except (ConnectionResetError, BrokenPipeError):
            oom = 'worker connection closed'
        last = None
        for _ in range(30):
            try:
                last = request(path, 'action=check')
                if 'WORKER=' in last:
                    break
            except (OSError, RuntimeError):
                pass
            time.sleep(.1)
        replaced = last is not None and pid(last) != pid(second)
        logs = subprocess.run(['docker','logs',container], capture_output=True, text=True)
        combined = first + second + oom + (last or '') + logs.stdout + logs.stderr
        passed = reused and replaced and 'CURRENT_REQUEST_WARNING' in second and all(
            marker not in combined for marker in ['STALE_HANDLER','STALE_EXCEPTION','SHUTDOWN_RAN','CONTINUED'])
        report = {'branch':a.branch, 'passed':passed, 'same_worker_reused':reused,
                  'oom_worker_replaced':replaced, 'responses':[first, second, oom, last],
                  'fpm_log':logs.stdout + logs.stderr}
    finally:
        subprocess.run(['docker','rm','-f',container], capture_output=True)
    dest = root / 'work/reports' / ('php-' + a.branch + '-fpm.json')
    dest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'branch':a.branch, 'passed':passed, 'same_worker_reused':reused,
                      'oom_worker_replaced':replaced, 'report':str(dest)}))
    raise SystemExit(0 if passed else 1)
