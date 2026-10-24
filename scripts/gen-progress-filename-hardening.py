#!/usr/bin/env python3
"""Generate 003-harden-progress-filename.patch for every branch.

Hardens the CVE-2026-109619 injection vector while preserving upload progress:
percent-encode '<' in the upload-progress 'name' record only, so session files
can no longer contain PHP open tags. Benign filenames stay byte-identical
(rfc1867.phpt expectations use plain names and remain valid).

Diffs pristine sources; 001/002 leave this region untouched.
"""
import difflib
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]

PHPT = '''--TEST--
session rfc1867 upload progress filename keeps session file free of PHP open tags
--INI--
file_uploads=1
error_reporting=E_ALL&~E_NOTICE
upload_max_filesize=1024
session.save_path=
session.name=PHPSESSID
session.use_strict_mode=0
session.use_cookies=1
session.use_only_cookies=0
session.upload_progress.enabled=1
session.upload_progress.cleanup=0
session.upload_progress.prefix=upload_progress_
session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq=1%
session.upload_progress.min_freq=0.000000001
session.save_handler=files
--SKIPIF--
<?php include('skipif.inc'); ?>
--COOKIE--
PHPSESSID=rfc1867-enc-tests
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

rfc1867enc.php
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="file1"; filename="safe.txt"

1
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="file2"; filename="evil<?php echo 1; ?>b.txt"

2
-----------------------------20896060251896012921717172737--
--FILE--
<?php
session_start();
$progress = $_SESSION["upload_progress_rfc1867enc.php"];
var_dump($progress["files"][0]["name"]);
$stored = $progress["files"][1]["name"];
var_dump($stored);
var_dump(strpos($stored, '<') === false);
var_dump(strpos($stored, '%3C') !== false);
session_destroy();
?>
--EXPECT--
string(8) "safe.txt"
string(27) "evil%3C?php echo 1; ?>b.txt"
bool(true)
bool(true)
'''

HELPER = '''/* php2shell Chain A hardening (CVE-2026-109619 injection vector): upload
 * progress filenames are stored raw in session files. A filename containing
 * '<?' turns any later include/read-as-PHP of the session file into code
 * execution. Percent-encode '<' in the stored copy only; benign filenames
 * stay byte-identical. The uploaded file itself is untouched. */
static char *php_session_rfc1867_safe_name(const char *name)
{
\tchar *encoded, *w;
\tconst char *r;

\tif (!strchr(name, '<')) {
\t\treturn NULL;
\t}
\tencoded = emalloc(strlen(name) * 3 + 1);
\tfor (r = name, w = encoded; *r; r++) {
\t\tif (*r == '<') {
\t\t\tmemcpy(w, "%3C", 3);
\t\t\tw += 3;
\t\t} else {
\t\t\t*w++ = *r;
\t\t}
\t}
\t*w = '\\0';
\treturn encoded;
}

'''

for branch in ['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.1']:
    old_src = (root / f'php-{branch}/ext/session/session.c').read_text()

    # 1. Insert the helper before the callback definition.
    marker = 'static int php_session_rfc1867_callback(unsigned int event, void *event_data, void **extra'
    assert old_src.count(marker) >= 1, branch
    def_idx = old_src.index(marker + (' TSRMLS_DC' if branch.startswith('5.') else ''))
    new_src = old_src[:def_idx] + HELPER + old_src[def_idx:]

    # 2. Encode the stored name at the call site (line-level replace).
    lines = new_src.splitlines(True)
    hits = [i for i, l in enumerate(lines)
            if 'add_assoc_string_ex' in l and '"name"' in l and '*data->filename' in l]
    assert len(hits) == 1, branch + ' call site'
    i = hits[0]
    if branch.startswith('5.'):
        indent = '\t\t\t'
        call = (indent + '{ /* php2shell Chain A hardening: no PHP open tags in session files. */\n'
                + indent + '\tchar *safe_name = php_session_rfc1867_safe_name(*data->filename);\n'
                + indent + '\tadd_assoc_string_ex(progress->current_file, "name",'
                  '          sizeof("name"),            safe_name ? safe_name : *data->filename, 1);\n'
                + indent + '\tif (safe_name) {\n' + indent + '\t\tefree(safe_name);\n' + indent + '\t}\n'
                + indent + '}\n')
    else:
        indent = '\t\t\t'
        call = (indent + '{ /* php2shell Chain A hardening: no PHP open tags in session files. */\n'
                + indent + '\tchar *safe_name = php_session_rfc1867_safe_name(*data->filename);\n'
                + indent + '\tadd_assoc_string_ex(&progress->current_file, "name",'
                  ' sizeof("name") - 1, safe_name ? safe_name : *data->filename);\n'
                + indent + '\tif (safe_name) {\n' + indent + '\t\tefree(safe_name);\n' + indent + '\t}\n'
                + indent + '}\n')
    new_src = ''.join(lines[:i]) + call + ''.join(lines[i + 1:])

    diff = ''.join(difflib.unified_diff(
        old_src.splitlines(True), new_src.splitlines(True),
        fromfile='a/ext/session/session.c', tofile='b/ext/session/session.c'))
    diff += ''.join(difflib.unified_diff(
        [], PHPT.splitlines(True),
        fromfile='/dev/null', tofile='b/ext/session/tests/rfc1867_filename_encoding.phpt'))

    path = root / f'php-{branch}-patches/CVE-2026-109619/003-harden-progress-filename.patch'
    path.write_text(diff)
    print(json.dumps({'branch': branch, 'path': str(path.relative_to(root)),
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))
