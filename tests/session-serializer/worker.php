<?php
// Scalar-only regression endpoint. Executed exclusively by local CGI tests.
$errors = [];
set_error_handler(function ($severity, $message) use (&$errors) { $errors[] = $message; return true; });
$source = ini_get('session.serialize_handler');
$target = getenv('TARGET_SERIALIZER');
$file = ini_get('session.save_path') . '/sess_probe';
$before = file_exists($file) ? file_get_contents($file) : null;
$change = null;
if (getenv('CHANGE_API') === 'options') {
    $started = session_start(['serialize_handler' => $target]);
} else {
    $change = ini_set('session.serialize_handler', $target);
    $started = session_start();
}
$current = ini_get('session.serialize_handler');
$progress = isset($_SESSION['upload_progress_probe']['bytes_processed']);
$session = $_SESSION ?? null;
$after = file_exists($file) ? file_get_contents($file) : null;
if (session_status() === PHP_SESSION_ACTIVE) session_abort();
echo json_encode(compact('source', 'target', 'current', 'change', 'started', 'progress', 'before', 'after', 'session', 'errors'));
