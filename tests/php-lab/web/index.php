<?php
/* Adapted from ../block-phpshell/lab/index.php (local PHP2Shell lab fixture).
 * Harmless forwarding fixture; contains no command execution or exploit payload.
 * getallheaders() polyfill added for SAPIs lacking it (CLI server < 7.3). */
if (!function_exists('getallheaders')) {
    function getallheaders() {
        $h = [];
        foreach ($_SERVER as $k => $v) {
            if (strpos($k, 'HTTP_') === 0) {
                $h[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($k, 5)))))] = $v;
            }
        }
        return $h;
    }
}
$path = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : '/';
if ($path === '/binary') {
    header('Content-Type: application/octet-stream');
    echo file_get_contents('php://input');
    exit;
}
if ($path === '/fatal') {
    http_response_code(500);
    exit;
}
if ($path === '/unserialize') {
    // Chain B delivery sink (var_destroy UAF, CVE-2026-109618): an application
    // feeding request input straight to unserialize(). Reports only what PHP
    // consumed — no gadget objects are defined here, so nothing can execute.
    $d = '';
    if (isset($_POST['d'])) { $d = $_POST['d']; }
    elseif (isset($_COOKIE['d'])) { $d = $_COOKIE['d']; }
    elseif (isset($_GET['d'])) { $d = $_GET['d']; }
    $r = @unserialize($d);
    $verdict = $r === false ? 'false' : (is_array($r) ? 'array:' . count($r) : gettype($r));
    echo json_encode(['fed_bytes' => strlen($d), 'unserialize' => $verdict]);
    exit;
}
if ($path === '/session') {
    session_start();
}
if ($path === '/session-bad') {
    header('Set-Cookie: PHPSESSID=not.a.session.id; path=/');
}
if ($path === '/status') {
    http_response_code(422);
    header('Set-Cookie: first=1', false);
    header('Set-Cookie: second=2', false);
}
header('Content-Type: application/json');
echo json_encode([
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'headers' => array_change_key_case(getallheaders(), CASE_LOWER),
    'body_base64' => base64_encode(file_get_contents('php://input')),
    'content_length' => isset($_SERVER['CONTENT_LENGTH']) ? $_SERVER['CONTENT_LENGTH'] : null,
    'post_keys' => array_keys($_POST),
    'file_keys' => array_keys($_FILES),
    'pid' => getmypid(),
    'ini' => [
        'session.upload_progress.enabled' => ini_get('session.upload_progress.enabled'),
        'memory_limit' => ini_get('memory_limit'),
        'max_input_nesting_level' => ini_get('max_input_nesting_level'),
    ],
]);
