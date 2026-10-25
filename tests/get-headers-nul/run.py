#!/usr/bin/env python3
"""CVE-2020-7066 (bug #79329): get_headers() must not silently truncate a URL at
a NUL byte.

The child opens an ephemeral listening socket, then asks get_headers() for a URL
whose host is that socket and whose path contains NUL plus a tail. A vulnerable
build connects and the request line stops at the NUL; a fixed build refuses the
argument and never connects. Both facts are observed, not echoed.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

PAYLOAD = r'''<?php
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if (!$server) { echo json_encode(array('error' => 'listen failed')); exit(3); }
$name = stream_socket_get_name($server, false);
ini_set('default_socket_timeout', 1);
$warning = null;
set_error_handler(function ($no, $str) use (&$warning) { $warning = $str; return true; });
$url = 'http://' . $name . '/aaaa' . "\0" . '/secret';
$result = get_headers($url);
restore_error_handler();
stream_set_blocking($server, false);
$client = @stream_socket_accept($server, 1);
$line = $client ? trim((string)fgets($client)) : null;
echo json_encode(array(
    'connected' => $client !== false && $client !== null,
    'request_line' => $line,
    'returned' => $result === false ? 'false' : gettype($result),
    'warning' => $warning,
    'marker' => 137 * 149,
)), "\n";
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', required=True)
    p.add_argument('--expect', choices=['fixed', 'vulnerable'], default='fixed')
    p.add_argument('--report', required=True)
    args = p.parse_args()
    report = dict(image=args.image, expectation=args.expect)
    with tempfile.TemporaryDirectory(prefix='get-headers-7066-') as directory:
        (Path(directory) / 'p.php').write_text(PAYLOAD)
        run = subprocess.run(
            ['docker', 'run', '--rm', '--network', 'none', '-v', directory + ':/t',
             args.image, 'sapi/cli/php', '/t/p.php'],
            capture_output=True, text=True)
        report.update(exit=run.returncode, stdout=run.stdout, stderr=run.stderr)
    line = report['stdout'].strip().splitlines()[-1] if report['stdout'].strip() else ''
    try:
        result = json.loads(line)
    except ValueError:
        report.update(passed=False, error='no parsable result')
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        return 1
    report['result'] = result
    connected = bool(result.get('connected'))
    # Truncation is proven only by a request line that ends at the NUL.
    truncated = connected and (result.get('request_line') or '').upper().startswith('GET /AAAA ')
    sane = result.get('marker') == 20413 and report['exit'] == 0
    fixed = (not connected) and result.get('returned') in ('false', 'NULL')
    report['truncated'] = truncated
    report['passed'] = bool(sane and (fixed if args.expect == 'fixed' else truncated))
    dest = Path(args.report)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
