#!/usr/bin/env python3
"""Port the CVE-2026-109618/109619 mitigation to PHP 8.0 from the 8.1 series.

8.0 died before the advisory, so there is no upstream commit for it. The 8.1
patch (1d7dec17) is the closest source; most of it applies verbatim, three files
need a hand port, and two groups of hunks are deliberately dropped:

* ext/opcache/* -- 8.1 hardened the "pending CE cache" slots stored in interned
  strings. 8.0 has no such mechanism (no zend_accel_get_class_name_map_ptr, no
  pending_ce_cache), so there is nothing to harden. Excluded, not skipped.
* ext/zend_test/tests/* -- observer-API test expectations that only match
  8.1's zend_test fixture. Excluded so 8.0's own suite stays meaningful.

Run: python3 scripts/gen-php80-port.py   (needs php-8.0/ pristine + the 8.1 series)
"""
import difflib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_81 = ROOT / 'php-8.1-patches'
DEST = ROOT / 'php-8.0-patches'
WORK = Path('/tmp/esphp-php80-port')

SERIES = [
    ('CVE-2026-109618/001-avoid-state-corruption.patch', '001-avoid-state-corruption.patch'),
    ('CVE-2026-109619/002-restore-upload-progress.patch', '002-restore-upload-progress.patch'),
    ('CVE-2026-109619/003-harden-progress-record.patch', '003-harden-progress-record.patch'),
]

# --- hand ports for the hunks that do not apply to 8.0 ----------------------
EXEC_API = 'Zend/zend_execute_API.c'
HASH = 'Zend/zend_hash.c'
MAIN = 'main/main.c'

EXEC_ANCHOR = '\tzend_objects_store_free_object_storage(&EG(objects_store), fast_shutdown);\n'
EXEC_ADD = '''\tzend_objects_store_free_object_storage(&EG(objects_store), fast_shutdown);

\t/* 8.1 resets these after zend_shutdown_executor_values(); 8.0 has a single
\t * shutdown_executor(), so the reset belongs here. Anything reachable from
\t * zend_error_zstr_at() before init_executor() must not point at freed state
\t * (CVE-2026-109618 teardown correctness). */
\tZVAL_UNDEF(&EG(user_error_handler));
\tZVAL_UNDEF(&EG(user_exception_handler));
\tmemset(&EG(user_error_handlers_error_reporting), 0, sizeof(EG(user_error_handlers_error_reporting)));
\tmemset(&EG(user_error_handlers), 0, sizeof(EG(user_error_handlers)));
\tmemset(&EG(user_exception_handlers), 0, sizeof(EG(user_exception_handlers)));
\t/* 8.0 has no EG(record_errors)/EG(errors): the error-recording API arrived
\t * in 8.1, so only the state 8.0 actually has is reset here. */
\tEG(error_handling) = EH_NORMAL;
\tEG(exception) = NULL;
'''

FAST_ANCHOR = '\t\tzend_cleanup_internal_classes();\n\t} else {\n'
FAST_ADD = '''\t\tzend_cleanup_internal_classes();
\t\t/* The object store is discarded with the arena; leave no dangling
\t\t * bucket pointer for a late error path to walk. */
\t\tEG(objects_store).object_buckets = NULL;
\t\tEG(objects_store).top = 1;
\t} else {
'''

HASH_OLD = '\t\tzend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%u * %zu + %zu)", ht->nTableSize * 2, sizeof(Bucket), sizeof(Bucket));\n'
HASH_NEW = '\t\tzend_mm_safe_error_ex("Possible integer overflow in memory allocation (%u * %zu + %zu)", ht->nTableSize * 2, sizeof(Bucket), sizeof(Bucket));\n'

MAIN_ANCHOR = '\tzend_interned_strings_deactivate();\n'
MAIN_ADD = '\tzend_interned_strings_deactivate();\n\tclear_last_error();\n'


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def apply_patch(tree, patch):
    proc = subprocess.run(['patch', '-p1', '--batch', '--fuzz=0', '-d', str(tree)],
                          stdin=patch.open(), capture_output=True, text=True)
    return proc


def edit(tree, rel, old, new, count=1):
    path = tree / rel
    text = path.read_text()
    if text.count(old) != count:
        raise SystemExit(f'{rel}: expected {count} match(es), found {text.count(old)}')
    path.write_text(text.replace(old, new, count))


def scrub(tree):
    for junk in list(tree.rglob('*.rej')) + list(tree.rglob('*.orig')):
        junk.unlink()


def diff_trees(before, after):
    out = []
    rels = sorted({p.relative_to(after) for p in after.rglob('*') if p.is_file()}
                  | {p.relative_to(before) for p in before.rglob('*') if p.is_file()})
    for rel in rels:
        # opcache: every hunk of the 8.1 commit belongs to the pending
        # CE-cache publication mechanism, which 8.0 does not have. Applying a
        # subset would add calls to functions that do not exist there.
        if rel.parts[:2] in {('ext', 'zend_test'), ('ext', 'opcache')}:
            continue
        a, b = before / rel, after / rel
        if not a.exists() or not b.exists():
            continue
        at, bt = a.read_bytes(), b.read_bytes()
        if at == bt:
            continue
        out.append(''.join(difflib.unified_diff(
            at.decode('utf-8', 'surrogateescape').splitlines(True),
            bt.decode('utf-8', 'surrogateescape').splitlines(True),
            fromfile=f'a/{rel}', tofile=f'b/{rel}')))
    return ''.join(out)


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    pristine = WORK / 'pristine'
    shutil.copytree(ROOT / 'php-8.0', pristine, symlinks=True)

    # 001: apply the 8.1 patch, then repair what 8.0 does differently.
    step = WORK / 'p001'
    shutil.copytree(pristine, step, symlinks=True)
    proc = apply_patch(step, SRC_81 / SERIES[0][0])
    failed = [line.split()[-1] for line in proc.stdout.splitlines() if 'FAILED' in line]
    print(f'001: {len(failed)} rejected hunk(s) to hand port')
    scrub(step)
    edit(step, EXEC_API, EXEC_ANCHOR, EXEC_ADD)
    edit(step, EXEC_API, FAST_ANCHOR, FAST_ADD)
    edit(step, HASH, HASH_OLD, HASH_NEW)
    edit(step, MAIN, MAIN_ANCHOR, MAIN_ADD)

    # 002 and 003 are session.c only and apply verbatim.
    step2 = WORK / 'p002'
    shutil.copytree(step, step2, symlinks=True)
    r2 = apply_patch(step2, SRC_81 / SERIES[1][0])
    if r2.returncode != 0:
        raise SystemExit('002 failed:\n' + r2.stdout)
    scrub(step2)
    step3 = WORK / 'p003'
    shutil.copytree(step2, step3, symlinks=True)
    r3 = apply_patch(step3, SRC_81 / SERIES[2][0])
    if r3.returncode != 0:
        raise SystemExit('003 failed:\n' + r3.stdout)
    scrub(step3)

    DEST.mkdir(exist_ok=True)
    headers = {
        0: ('Subject: [PATCH] PHP 8.0 port of the combined CVE-2026-109618/109619 mitigation\n'
            'Source: PHP 8.1 patch 1d7dec178a094e6e75b229ce22754045f8c6070a\n'
            'Excluded: ext/opcache (8.0 has no pending CE-cache mechanism),\n'
            '          ext/zend_test (8.1-only observer test expectations)\n'
            'Hand-ported: Zend/zend_execute_API.c, Zend/zend_hash.c, main/main.c\n\n'),
        1: ('Subject: [PATCH] Restore session upload progress (compatibility override)\n'
            'Not a security fix: reverses the mitigation\'s feature removal by explicit policy.\n\n'),
        2: ('Subject: [PATCH] Harden the upload-progress record (encode <, | and NUL)\n\n'),
    }
    bodies = [diff_trees(pristine, step), diff_trees(step, step2), diff_trees(step2, step3)]
    for (src_rel, name), header, body in zip(SERIES, headers.values(), bodies):
        dest = DEST / src_rel            # keep the CVE-<id>/<file> layout
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(header + body)
        print(f'{dest.relative_to(ROOT)}: {len(body.splitlines())} lines')
    return 0


if __name__ == '__main__':
    sys.exit(main())
