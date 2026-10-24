<?php
/* Disposable PHP 5.4 blog fixture. No production deployment. */
header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
session_start();
function esc($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function fail($code, $message) { http_response_code($code); exit(esc($message)); }
function token() {
    $f = fopen('/dev/urandom', 'rb');
    $v = fread($f, 24); fclose($f);
    if (strlen($v) !== 24) fail(500, 'Random source unavailable');
    return bin2hex($v);
}
/* Constant-time compare without ext/hash, which this --disable-all build omits. */
function same($a, $b) {
    if (!is_string($a) || !is_string($b) || strlen($a) !== strlen($b)) return false;
    $diff = 0;
    for ($i = 0; $i < strlen($a); $i++) $diff |= ord($a[$i]) ^ ord($b[$i]);
    return $diff === 0;
}
if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = token();
$csrf = $_SESSION['csrf'];
$action = isset($_GET['action']) ? $_GET['action'] : '';
$file = '/data/posts.json';
$posts = file_exists($file) ? json_decode(file_get_contents($file), true) : array();
if (!is_array($posts)) fail(500, 'Invalid blog storage');
$logged = !empty($_SESSION['editor']);
if ($action === 'health') {
    header('Content-Type: application/json');
    echo json_encode(array('version' => PHP_VERSION, 'pid' => getmypid(), 'progress' => ini_get('session.upload_progress.enabled')));
    exit;
}
if ($action === 'progress') {
    header('Content-Type: application/json');
    echo json_encode(isset($_SESSION['upload_progress_blog']) ? $_SESSION['upload_progress_blog'] : null);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf']) || $_POST['csrf'] !== $csrf) fail(403, 'CSRF rejected');
    if ($action === 'login') {
        $password = getenv('BLOG_PASSWORD');
        if (!$password || !isset($_POST['password']) || !same($_POST['password'], $password)) fail(403, 'Login rejected');
        session_regenerate_id(true); $_SESSION['editor'] = true;
    } else {
        if (!$logged) fail(403, 'Login required');
        if ($action === 'logout') {
            $_SESSION = array(); session_destroy();
        } elseif ($action === 'save') {
            $id = isset($_POST['id']) && preg_match('/^[0-9]+$/D', $_POST['id']) ? (int) $_POST['id'] : 0;
            $title = isset($_POST['title']) ? trim($_POST['title']) : '';
            $body = isset($_POST['body']) ? trim($_POST['body']) : '';
            if ($title === '' || strlen($title) > 120 || strlen($body) > 8000) fail(400, 'Title/body size invalid');
            if (!$id) {
                if (count($posts) >= 50) fail(400, '50-post lab limit');
                $id = count($posts) ? max(array_keys($posts)) + 1 : 1;
            } elseif (!isset($posts[$id])) fail(404, 'Post missing');
            $posts[$id] = array('title' => $title, 'body' => $body);
            file_put_contents($file, json_encode($posts), LOCK_EX);
        } elseif ($action === 'delete') {
            unset($posts[(int) $_POST['id']]);
            file_put_contents($file, json_encode($posts), LOCK_EX);
        } elseif ($action === 'upload') {
            if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) fail(400, 'Upload failed');
            $upload = $_FILES['image'];
            $info = @getimagesize($upload['tmp_name']);
            if (!$info || !in_array($info[2], array(IMAGETYPE_PNG, IMAGETYPE_JPEG, IMAGETYPE_GIF), true)) fail(400, 'PNG/JPEG/GIF required');
            if (count(glob('/data/uploads/*')) >= 8) fail(400, '8-image lab limit');
            $name = token();
            if (!move_uploaded_file($upload['tmp_name'], '/data/uploads/' . $name)) fail(500, 'Cannot store upload');
            $_SESSION['image'] = $name;
        } else fail(400, 'Unknown action');
    }
    header('Location: /'); exit;
}
if ($action === 'image') {
    $name = isset($_GET['id']) ? $_GET['id'] : '';
    if (!preg_match('/^[a-f0-9]{48}$/D', $name) || !is_file('/data/uploads/' . $name)) fail(404, 'Image missing');
    $info = getimagesize('/data/uploads/' . $name);
    header('Content-Type: ' . $info['mime']);
    readfile('/data/uploads/' . $name); exit;
}
?>
<!doctype html><meta charset="utf-8"><title>Tiny PHP blog lab</title>
<style>body{max-width:720px;margin:30px auto;font:16px sans-serif;padding:12px}input,textarea{display:block;margin:8px 0;width:95%}article{border-top:1px solid #ccc;padding:12px 0}img{max-width:300px}</style>
<h1>Tiny PHP blog lab</h1><p>PHP <?php echo esc(PHP_VERSION); ?> · Disposable local test data</p>
<?php if (!$logged) { ?>
<form method="post" action="?action=login"><input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="password" name="password" placeholder="Lab password"><button>Login</button></form>
<?php } else { ?>
<form method="post" action="?action=logout"><input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><button>Logout</button></form>
<h2>Write a post</h2>
<form method="post" action="?action=save"><input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input name="id" placeholder="Existing post ID to edit; blank for new"><input name="title" maxlength="120" placeholder="Title" required><textarea name="body" maxlength="8000" placeholder="Plain text body"></textarea><button>Save</button></form>
<h2>Image upload</h2>
<form method="post" enctype="multipart/form-data" action="?action=upload"><input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="blog"><input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="file" name="image" accept="image/png,image/jpeg,image/gif"><button>Upload (1 MiB max)</button></form>
<p><a href="?action=progress">Last upload progress record</a> (single worker: available after upload)</p>
<?php if (isset($_SESSION['image'])) { ?><img src="?action=image&amp;id=<?php echo esc($_SESSION['image']); ?>" alt="Uploaded image"><?php } ?>
<?php } ?>
<?php foreach ($posts as $id => $post) { ?>
<article><h2><?php echo esc($post['title']); ?></h2><small>Post #<?php echo (int) $id; ?></small><p><?php echo nl2br(esc($post['body'])); ?></p>
<?php if ($logged) { ?><form method="post" action="?action=delete"><input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="hidden" name="id" value="<?php echo (int) $id; ?>"><button>Delete</button></form><?php } ?></article>
<?php } ?>
