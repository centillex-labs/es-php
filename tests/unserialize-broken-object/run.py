#!/usr/bin/env python3
"""CVE-2016-7124 (bug #72663): a failed unserialize() must not leave a
partially constructed object reachable.

The marker is computed, not echoed from the payload: the child reports the PHP
type of the reference that pointed at the half-built object. A patched build
reports NULL; an unpatched build reports object.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

PAYLOAD = r'''<?php
class obj implements Serializable {
    var $data;
    function serialize() { return serialize($this->data); }
    function unserialize($data) { $this->data = unserialize($data); }
}
$inner = 'a:1:{i:0;O:9:"Exception":2:{s:7:"'."\0".'*'."\0".'file";R:4;}';
$exploit = 'a:2:{i:0;C:3:"obj":'.strlen($inner).':{'.$inner.'}i:1;R:4;}';
$data = unserialize($exploit);
$ref = (is_array($data) && array_key_exists(1, $data)) ? gettype($data[1]) : 'missing';
echo json_encode(array(
    'top' => gettype($data),
    'count' => is_array($data) ? count($data) : -1,
    'ref_type' => $ref,
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
    with tempfile.TemporaryDirectory(prefix='unserialize-7124-') as directory:
        (Path(directory) / 'p.php').write_text(PAYLOAD)
        run = subprocess.run(
            ['docker', 'run', '--rm', '--network', 'none', '-v', directory + ':/t',
             args.image, 'sapi/cli/php', '/t/p.php'],
            capture_output=True, text=True)
        report['exit'] = run.returncode
        report['stdout'] = run.stdout
        report['stderr'] = run.stderr
    line = report['stdout'].strip().splitlines()[-1] if report['stdout'].strip() else ''
    try:
        result = json.loads(line)
    except ValueError:
        report['error'] = 'no parsable result'
        report['passed'] = False
        Path(args.report).write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        return 1
    report['result'] = result
    sane = (result.get('marker') == 20413 and result.get('top') == 'array'
            and result.get('count') == 2 and report['exit'] == 0)
    wiped = result.get('ref_type') == 'NULL'
    report['object_wiped'] = wiped
    # A fixed build must both stay sane and wipe the object; a vulnerable
    # control must stay sane and leave the object reachable.
    report['passed'] = bool(sane and (wiped if args.expect == 'fixed' else not wiped))
    dest = Path(args.report)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
