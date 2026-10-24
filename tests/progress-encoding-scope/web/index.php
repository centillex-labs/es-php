<?php
/* Upload-progress encoding scope probe.
 *
 * Reports both sides of the boundary so the test can assert what patch 003
 * changes and, just as importantly, what it must NOT change:
 *
 *   $_FILES[...]['name']                      must stay raw
 *   $_SESSION['upload_progress_*'] key        encoded ('<' and '|')
 *   $_SESSION[...]['files'][i]['name']        encoded ('<' and '|', but NOT '>')
 *   $_SESSION[...]['files'][i]['field_name']  encoded
 *
 * '>' is deliberately left alone: no PHP tag opens with it, so encoding it
 * would mutate benign filenames for no security gain. */
session_start();

$key = null;
foreach ($_SESSION as $k => $v) {
    if (strncmp($k, 'upload_progress_', 16) === 0) { $key = $k; break; }
}

$files = array();
if ($key !== null && isset($_SESSION[$key]['files'])) {
    foreach ($_SESSION[$key]['files'] as $file) {
        $files[] = array(
            'field_name' => isset($file['field_name']) ? $file['field_name'] : null,
            'name'       => isset($file['name'])       ? $file['name']       : null,
        );
    }
}

$out = array(
    'files_name'     => isset($_FILES['f']['name']) ? $_FILES['f']['name'] : null,
    'session_key'    => $key,
    'progress_files' => $files,
);

header('Content-Type: application/json');
echo json_encode($out);
