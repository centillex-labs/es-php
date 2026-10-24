<?php
/* INTENTIONALLY UNSAFE. Local disposable lab only. Never expose publicly. */
if (getenv('BLOG_LAB_ENABLED') !== '1') { http_response_code(404); exit; }
// Narrow LFI sink: only local session files, no arbitrary paths/wrappers.
// Do not session_start here: inspect the on-disk record without rewriting it.
$sid = isset($_GET['sid']) ? $_GET['sid'] : '';
if (!preg_match('/^[a-zA-Z0-9,-]{1,64}$/D', $sid)) { http_response_code(400); exit('Session ID required'); }
$file = '/data/sessions/sess_' . $sid;
if (!is_file($file)) { http_response_code(404); exit('Session missing'); }
header('Content-Type: text/plain');
include $file;
