#!/usr/bin/env python3
"""Generate 003-harden-progress-record.patch for every branch.

CVE-2026-109619 hardening for the session upload-progress record, while
preserving the feature.

PHP takes three values straight from the request and writes them into the
session file:

  1. the session key suffix  <- the PHP_SESSION_UPLOAD_PROGRESS field value
  2. the per-file field_name <- the multipart field name
  3. the per-file name       <- the uploaded filename

Two characters in any of them are dangerous:

  '<'  lets the session file open a PHP tag, so any later include (or
       read-as-PHP) of the session file executes attacker code.
  '|'  is the php/php_serialize session serializer delimiter, so a value
       carrying one shifts the parse boundary and can inject an object.
  NUL  is the php_binary delimiter; filenames cannot contain it anyway.

All three sites now percent-encode those bytes in the stored copy only.
Benign values stay byte-identical, the uploaded file is untouched, and the
INI control over the feature is unchanged.

Diffs pristine sources; 001/002 leave these regions untouched.
"""
import difflib
import hashlib
import json
import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]

BRANCHES = ['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.1']

PHPT = '''--TEST--
session rfc1867 upload progress keeps PHP tags and serializer delimiters out of session data
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

p<1
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="f1"; filename="safe.txt"

1
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="f<2"; filename="evil<?php echo 1; ?>b.txt"

2
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="f3"; filename="pipe|x.txt"

3
-----------------------------20896060251896012921717172737--
--FILE--
<?php
session_start();
$key = NULL;
foreach ($_SESSION as $k => $v) {
    if (strncmp($k, "upload_progress_", 16) === 0) { $key = $k; break; }
}
var_dump($key);
foreach ($_SESSION[$key]["files"] as $file) {
    var_dump($file["field_name"], $file["name"]);
}
$blob = serialize($_SESSION);
var_dump(strpos($blob, "<") === false);
var_dump(strpos($blob, "|") === false);
session_destroy();
?>
--EXPECT--
string(21) "upload_progress_p%3C1"
string(2) "f1"
string(8) "safe.txt"
string(5) "f%3C2"
string(27) "evil%3C?php echo 1; ?>b.txt"
string(2) "f3"
string(12) "pipe%7Cx.txt"
bool(true)
bool(true)
'''

HELPER = '''/* php2shell hardening (CVE-2026-109619). Upload-progress values are taken
 * straight from the request and written into the session file. '<' lets that
 * file open a PHP tag, so any later include/read-as-PHP of the session file
 * executes attacker code. '|' and NUL are session serializer delimiters, so a
 * value carrying one shifts the parse boundary and can inject an object.
 * Percent-encode those bytes in the stored copy only: benign values stay
 * byte-identical and the uploaded file itself is untouched. */
static char *php_session_rfc1867_safe_str(const char *value, size_t value_len)
{
\tchar *encoded, *w;
\tsize_t i;
\tint needs_encode = 0;

\tfor (i = 0; i < value_len; i++) {
\t\tif (value[i] == '<' || value[i] == '|' || value[i] == '\\0') {
\t\t\tneeds_encode = 1;
\t\t\tbreak;
\t\t}
\t}
\tif (!needs_encode) {
\t\treturn NULL;
\t}
\tencoded = emalloc(value_len * 3 + 1);
\tfor (i = 0, w = encoded; i < value_len; i++) {
\t\tswitch (value[i]) {
\t\tcase '<':  memcpy(w, "%3C", 3); w += 3; break;
\t\tcase '|':  memcpy(w, "%7C", 3); w += 3; break;
\t\tcase '\\0': memcpy(w, "%00", 3); w += 3; break;
\t\tdefault:   *w++ = value[i];     break;
\t\t}
\t}
\t*w = '\\0';
\treturn encoded;
}

'''


def assoc_call(branch, key, value_expr, indent):
    """Build an add_assoc_string_ex call in the branch's signature."""
    if branch.startswith('5.'):
        return (f'{indent}add_assoc_string_ex(progress->current_file, "{key}", '
                f'sizeof("{key}"), {value_expr}, 1);\n')
    return (f'{indent}add_assoc_string_ex(&progress->current_file, "{key}", '
            f'sizeof("{key}") - 1, {value_expr});\n')


def encode_block(branch, key, value_expr, length_expr, indent, var):
    """Wrap a value site so it stores an encoded copy when needed."""
    return (
        f'{indent}{{ /* php2shell hardening: no PHP tags or serializer delimiters. */\n'
        f'{indent}\tchar *{var} = php_session_rfc1867_safe_str({value_expr}, {length_expr});\n'
        + assoc_call(branch, key, f'{var} ? {var} : {value_expr}', indent + '\t')
        + f'{indent}\tif ({var}) {{\n'
        f'{indent}\t\tefree({var});\n'
        f'{indent}\t}}\n'
        f'{indent}}}\n'
    )


def replace_line(lines, predicate, replacement, branch, what):
    hits = [i for i, line in enumerate(lines) if predicate(line)]
    assert len(hits) == 1, f'{branch}: expected 1 {what} site, found {len(hits)}'
    i = hits[0]
    indent = re.match(r'[ \t]*', lines[i]).group(0)
    return lines[:i] + [replacement(indent)] + lines[i + 1:]


for branch in BRANCHES:
    old_src = (root / f'php-{branch}/ext/session/session.c').read_text()

    # 1. Insert the shared helper before the callback definition.
    marker = ('static int php_session_rfc1867_callback'
              '(unsigned int event, void *event_data, void **extra')
    suffix = ' TSRMLS_DC' if branch.startswith('5.') else ''
    # Two hits: the forward declaration and the definition. Inserting before the
    # first is what the original generator did and keeps the helper above both.
    assert old_src.count(marker + suffix) >= 1, f'{branch}: callback marker'
    idx = old_src.index(marker + suffix)
    new_src = old_src[:idx] + HELPER + old_src[idx:]

    # 2. Session key suffix <- PHP_SESSION_UPLOAD_PROGRESS value.
    lines = new_src.splitlines(True)

    def key_repl(indent):
        return (
            f'{indent}{{ /* php2shell hardening: keep "<" and "|" out of the session key. */\n'
            f'{indent}\tchar *safe_value = php_session_rfc1867_safe_str(*data->value, value_len);\n'
            f'{indent}\tif (safe_value) {{\n'
            f'{indent}\t\tsmart_str_appendl(&progress->key, safe_value, strlen(safe_value));\n'
            f'{indent}\t\tefree(safe_value);\n'
            f'{indent}\t}} else {{\n'
            f'{indent}\t\tsmart_str_appendl(&progress->key, *data->value, value_len);\n'
            f'{indent}\t}}\n'
            f'{indent}}}\n'
        )

    lines = replace_line(
        lines,
        lambda l: 'smart_str_appendl(&progress->key, *data->value, value_len)' in l,
        key_repl, branch, 'session key')

    # 3. Per-file field_name <- multipart field name.
    lines = replace_line(
        lines,
        lambda l: ('add_assoc_string_ex' in l and '"field_name"' in l
                   and 'data->name' in l),
        lambda indent: encode_block(branch, 'field_name', 'data->name',
                                    'strlen(data->name)', indent, 'safe_field'),
        branch, 'field_name')

    # 4. Per-file name <- uploaded filename.
    lines = replace_line(
        lines,
        lambda l: ('add_assoc_string_ex' in l and '"name"' in l
                   and '*data->filename' in l),
        lambda indent: encode_block(branch, 'name', '*data->filename',
                                    'strlen(*data->filename)', indent, 'safe_name'),
        branch, 'name')

    new_src = ''.join(lines)

    diff = ''.join(difflib.unified_diff(
        old_src.splitlines(True), new_src.splitlines(True),
        fromfile='a/ext/session/session.c', tofile='b/ext/session/session.c'))
    diff += ''.join(difflib.unified_diff(
        [], PHPT.splitlines(True),
        fromfile='/dev/null',
        tofile='b/ext/session/tests/rfc1867_progress_encoding.phpt'))

    path = root / f'php-{branch}-patches/CVE-2026-109619/003-harden-progress-record.patch'
    path.write_text(diff)
    print(json.dumps({'branch': branch, 'path': str(path.relative_to(root)),
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))
