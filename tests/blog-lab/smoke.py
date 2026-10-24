#!/usr/bin/env python3
"""Normal blog smoke checks; optional benign filename-injection probe."""
import argparse
import http.cookiejar
import os
import re
import urllib.request
import urllib.parse
import urllib.error
import uuid

p = argparse.ArgumentParser()
p.add_argument('--url', default='http://127.0.0.1:8054')
p.add_argument('--lab', action='store_true')
a = p.parse_args()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def request(path='/', data=None, headers=None):
    try:
        r = op.open(urllib.request.Request(a.url + path, data=data, headers=headers or {}), timeout=10)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
def post(action, values):
    return request('/?action=' + action, urllib.parse.urlencode(values).encode())
status, page = request()
assert status == 200
csrf = re.search('name="csrf" value="([a-f0-9]+)"', page)[1]
assert post('save', {'title': 'Denied'})[0] == 403
assert post('login', {'csrf': csrf, 'password': os.environ['BLOG_PASSWORD']})[0] == 200
assert post('save', {'csrf': csrf, 'title': '<test>', 'body': 'Hello blog'})[0] == 200
status, page = request()
assert '&lt;test&gt;' in page and 'Hello blog' in page
id_ = re.findall(r'Post #(\d+)', page)[-1]
assert post('save', {'csrf': csrf, 'id': id_, 'title': 'Edited', 'body': 'Updated'})[0] == 200
assert 'Updated' in request()[1]
assert post('delete', {'csrf': csrf, 'id': id_})[0] == 200
assert 'Updated' not in request()[1]
print('PASS: login, CSRF, create, escaped output, edit, delete')
if a.lab:
    sid = 'blogprobe' + uuid.uuid4().hex
    # Computed marker is NOT present in the source: reflection cannot pass.
    marker = 'BLOG_EXEC_' + str(213 * 317)
    filename = "<?php echo 'BLOG_EXEC_'.(213*317); ?>.png"
    boundary = 'BlogBoundary'
    body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nblog\r\n'
            '--' + boundary + '\r\nContent-Disposition: form-data; name="image"; filename="' + filename + '"\r\n'
            'Content-Type: image/png\r\n\r\nnot-an-image\r\n--' + boundary + '--\r\n').encode()
    # Rejected by the application, but upload progress runs before application code.
    request('/?action=upload', body, {'Content-Type': 'multipart/form-data; boundary=' + boundary, 'Cookie': 'PHPSESSID=' + sid})
    status, result = request('/lab.php?sid=' + sid)
    assert status == 200, 'Lab disabled or progress session missing'
    if marker in result:
        print('VULNERABLE: computed marker executed through session-file include')
        raise SystemExit(2)
    assert '%3C?php' in result, 'Inconclusive: expected encoded filename missing'
    print('PASS: filename encoded; computed marker did not execute (specific vector only)')
else:
    assert request('/lab.php?sid=test')[0] == 404, 'Unsafe lab unexpectedly enabled'
    print('PASS: unsafe lab disabled')
