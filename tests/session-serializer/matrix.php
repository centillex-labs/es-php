<?php
// Runs inside a network-disabled Docker container, not on a public endpoint.
$serializers = ['php', 'php_binary', 'php_serialize'];
$dir = sys_get_temp_dir() . '/serializer-matrix-' . getmypid();
mkdir($dir);
$results = [];
function request($cmd, $env, $body) {
    $p = proc_open($cmd, [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes, null, $env);
    fwrite($pipes[0], $body); fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $err = stream_get_contents($pipes[2]); fclose($pipes[2]); $exit = proc_close($p);
    $split = preg_split('/\r?\n\r?\n/', $out, 2);
    $data = isset($split[1]) ? json_decode($split[1], true) : null;
    return [$data, $err, $exit];
}
try {
foreach ($serializers as $source) foreach ($serializers as $target)
foreach (['ini_set', 'options'] as $api) foreach ([false, true] as $upload)
foreach ([false, true] as $enabled) {
    foreach (glob("$dir/sess_*") as $file) unlink($file);
    $boundary = 'local-test-boundary';
    $body = $upload ? "--$boundary\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nprobe\r\n"
        . "--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"probe.txt\"\r\n\r\nhello\r\n--$boundary--\r\n" : '';
    $cmd = ['/usr/src/php/sapi/cgi/php-cgi', '-n', '-q'];
    $settings = ['session.save_path'=>$dir, 'session.serialize_handler'=>$source,
        'session.upload_progress.enabled'=>(int)$enabled, 'session.upload_progress.cleanup'=>0,
        'session.upload_progress.min_freq'=>0, 'session.cache_limiter'=>'', 'session.use_cookies'=>1,
        'session.use_only_cookies'=>1, 'session.use_strict_mode'=>0];
    foreach ($settings as $k=>$v) { $cmd[] = '-d'; $cmd[] = "$k=$v"; }
    $env = array_merge(getenv(), ['REDIRECT_STATUS'=>'1', 'REQUEST_METHOD'=>$upload?'POST':'GET',
        'CONTENT_TYPE'=>"multipart/form-data; boundary=$boundary", 'CONTENT_LENGTH'=>(string)strlen($body),
        'SCRIPT_FILENAME'=>__DIR__.'/worker.php', 'HTTP_COOKIE'=>'PHPSESSID=probe',
        'TARGET_SERIALIZER'=>$target, 'CHANGE_API'=>$api]);
    [$data, $err, $exit] = request($cmd, $env, $body);
    $expected = $enabled ? $source : $target;
    $passed = $exit === 0 && $err === '' && is_array($data)
        && $data['current'] === $expected && $data['started'] === true
        && $data['progress'] === ($enabled && $upload)
        && (!$enabled || !$upload || ($data['before'] !== null && $data['before'] === $data['after']))
        && (!$enabled || $source === $target || $api !== 'ini_set' || $data['change'] === false);
    $results[] = compact('source','target','api','upload','enabled','passed','data','err','exit');
    if ($upload && $enabled) {
        // Same persisted record, new CGI process, no upload on this request.
        $env['REQUEST_METHOD'] = 'GET';
        $env['CONTENT_LENGTH'] = '0';
        [$data, $err, $exit] = request($cmd, $env, '');
        $passed = $exit === 0 && $err === '' && is_array($data)
            && $data['current'] === $source && $data['started'] === true
            && $data['progress'] === true && $data['before'] !== null
            && $data['before'] === $data['after'];
        $results[] = ['phase'=>'persisted-followup'] + compact('source','target','api','passed','data','err','exit');
    }
}
} finally {
    foreach (glob("$dir/*") as $file) unlink($file);
    rmdir($dir);
}
$failed = count(array_filter($results, fn($r) => !$r['passed']));
echo json_encode(['total'=>count($results),'failed'=>$failed,'results'=>$results], JSON_PRETTY_PRINT), "\n";
exit($failed ? 1 : 0);
