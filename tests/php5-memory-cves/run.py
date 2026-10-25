#!/usr/bin/env python3
"""LTS 2 regression harness for the exif / bcmath / mbstring backports.

Each case declares the evidence it needs. A case only passes when the unpatched
baseline fails by the same mechanism the fix removes:

  ubsan        run under -fsanitize=bounds and require an out-of-bounds report on
               the baseline image and none on the patched image
  behavioural  require a specific wrong result on the baseline and the corrected
               result on the patched image
  unproven     kept in the ledger only; the platform cannot exhibit the defect,
               so no baseline can fail. Reported, never counted as a pass.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ASSETS = HERE / 'payloads'

CASES = {
    'mbstring-bug79037': dict(
        cve='CVE-2020-7060', payload='mbstring_79037.php', evidence='ubsan',
        ubsan_image='{branch}-ubsan', baseline_image='{branch}-ubsan-baseline',
        note='CP950 trail bytes below 0x40 walk past cp950_pua_tbl'),
    'mbstring-bug79037-behaviour': dict(
        cve='CVE-2020-7060', payload='mbstring_79037.php', evidence='behavioural',
        patched_image='{branch}-extras', baseline_image='{branch}-extras-baseline',
        baseline_must_contain='string(3) "', patched_must_contain='string(1) "?"',
        note='the out-of-bounds table entry is returned as a bogus character'),
    'bcmath-bug78878': dict(
        cve='CVE-2019-11046', payload='bcmath_78878.php', evidence='unproven',
        note='glibc isdigit() is ASCII-only; the CVE needs a platform where '
             'isdigit() accepts bytes >= 0x80 (the advisory names Windows)'),
    'exif-bug79282': dict(
        cve='CVE-2020-7064', payload='exif_79282.php', evidence='unproven',
        note='the trigger is a use-of-uninitialized-value only MemorySanitizer '
             'reports; the itemlen+1 allocation keeps the read inside the block'),
    'exif-bug76423': dict(
        cve='CVE-2018-14883', payload='exif_76423.php', evidence='unproven',
        note='offset+size overflow needs a 32-bit size_t; on amd64 the sum '
             'cannot wrap, so the documented trigger is not reachable'),
}

RUN = ('/usr/src/php/sapi/cli/php -d display_errors=1 -d error_reporting=32767 '
       '/work/{payload}')


def run(image, payload, workdir):
    # UBSan reports on stderr; merge so one call covers both streams.
    return subprocess.run(
        ['docker', 'run', '--rm', '--memory', '1g', '-v', f'{workdir}:/work',
         image, 'sh', '-c', RUN.format(payload=payload) + ' 2>&1'],
        capture_output=True, text=True, errors='replace')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--branch', required=True)
    p.add_argument('--only', action='append', choices=sorted(CASES))
    p.add_argument('--report', required=True)
    args = p.parse_args()
    report = dict(branch=args.branch, cases=[])
    ok = True
    with tempfile.TemporaryDirectory(prefix='php5-cves-') as directory:
        work = Path(directory)
        for name in (args.only or sorted(CASES)):
            case = CASES[name]
            payload = case['payload']
            (work / payload).write_text((ASSETS / payload).read_text())
            if 'bug76423.jpg' in payload:
                (work / 'bug76423.jpg').write_bytes((ASSETS / 'bug76423.jpg').read_bytes())
            entry = dict(name=name, cve=case['cve'], evidence=case['evidence'],
                         note=case['note'], outcome='unproven')
            if case['evidence'] == 'ubsan':
                base_img = 'es-php:' + case['baseline_image'].format(branch=args.branch)
                fix_img = 'es-php:' + case['ubsan_image'].format(branch=args.branch)
                base = run(base_img, payload, directory)
                fixed = run(fix_img, payload, directory)
                base_oob = 'out of bounds' in base.stdout
                fixed_oob = 'out of bounds' in fixed.stdout
                entry.update(baseline=dict(image=base_img, oob=base_oob,
                                           output=base.stdout[-2000:]),
                             patched=dict(image=fix_img, oob=fixed_oob,
                                          output=fixed.stdout[-2000:]))
                entry['passed'] = bool(base_oob and not fixed_oob)
                entry['outcome'] = 'proven' if entry['passed'] else 'failed'
                ok &= entry['passed']
            elif case['evidence'] == 'behavioural':
                base_img = 'es-php:' + case['baseline_image'].format(branch=args.branch)
                fix_img = 'es-php:' + case['patched_image'].format(branch=args.branch)
                base = run(base_img, payload, directory)
                fixed = run(fix_img, payload, directory)
                base_wrong = case['baseline_must_contain'] in base.stdout
                fixed_right = case['patched_must_contain'] in fixed.stdout
                entry.update(baseline=dict(image=base_img, wrong=base_wrong,
                                           output=base.stdout[-2000:]),
                             patched=dict(image=fix_img, correct=fixed_right,
                                          output=fixed.stdout[-2000:]))
                entry['passed'] = bool(base_wrong and fixed_right)
                entry['outcome'] = 'proven' if entry['passed'] else 'failed'
                ok &= entry['passed']
            else:
                entry['path'] = 'php-' + args.branch
                entry['passed'] = None
            report['cases'].append(entry)
            print(f"{entry['outcome'].upper():10} {name} ({case['cve']})")
    report['passed'] = ok
    dest = Path(args.report)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
