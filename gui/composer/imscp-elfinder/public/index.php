<?php
/**
 * i-MSCP - internet Multi Server Control Panel
 * Copyright (C) 2010-2019 by Laurent Declercq <l.declercq@nuxwin.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * i-MSCP Web-based file manager front controller (login page, file manager
 * page and logout)
 */

declare(strict_types=1);

require_once __DIR__ . '/../library/bootstrap.php';

use iMSCP\ElFinder\App;

$app = imscp_elfinder_app();
App::sendSecurityHeaders();

try {
    $app->startSession();
} catch (\Throwable $e) {
    error_log('i-MSCP elFinder: ' . $e->getMessage());
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    echo "The file manager is not available.\n";
    exit;
}

$error = NULL;
$basePath = $app->getBasePath();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';

    if (!$app->checkCsrfToken($_POST['csrf_token'] ?? NULL)) {
        http_response_code(400);
        $error = 'Your session has expired. Please try again.';
    } elseif ($action === 'login') {
        if ($app->login($_POST['username'] ?? NULL, $_POST['password'] ?? NULL)) {
            header('Location: ' . $basePath, true, 303);
            exit;
        }

        if (($retryAfter = $app->getRetryAfter()) > 0) {
            http_response_code(429);
            header('Retry-After: ' . $retryAfter);
            $error = 'Too many failed login attempts. Please try again later.';
        } else {
            $error = 'Login failed. Please check your FTP username and password, or try again later.';
        }
    } elseif ($action === 'logout') {
        $app->logout();
        header('Location: ' . $basePath, true, 303);
        exit;
    } else {
        http_response_code(400);
        $error = 'Invalid request.';
    }
}

$identity = $app->getIdentity(true);
$csrfToken = $app->getCsrfToken();

header('Content-Type: text/html; charset=utf-8');

if (NULL === $identity) {
    $username = isset($_POST['username']) && is_string($_POST['username']) && strlen($_POST['username']) <= 255
        ? $_POST['username'] : '';
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>File manager - Login</title>
    <link rel="stylesheet" href="assets/imscp-elfinder.css">
</head>
<body class="login">
<main class="login-box">
    <h1>File manager</h1>
    <p class="hint">Log in with your FTP account credentials.</p>
    <?php if (NULL !== $error): ?>
        <p class="error" role="alert"><?= App::e($error) ?></p>
    <?php endif ?>
    <form method="post" action="<?= App::e($basePath) ?>" autocomplete="off">
        <input type="hidden" name="action" value="login">
        <input type="hidden" name="csrf_token" value="<?= App::e($csrfToken) ?>">
        <label for="username">FTP username</label>
        <input type="text" id="username" name="username" value="<?= App::e($username) ?>" maxlength="255" required autofocus autocapitalize="none" spellcheck="false">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" maxlength="1024" required>
        <button type="submit">Log in</button>
    </form>
</main>
</body>
</html>
<?php
    exit;
}

// Choose elFinder language from the Accept-Language header
$lang = 'en';
if (!empty($_SERVER['HTTP_ACCEPT_LANGUAGE']) && is_string($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
    foreach (explode(',', $_SERVER['HTTP_ACCEPT_LANGUAGE']) as $candidate) {
        $candidate = trim(explode(';', $candidate)[0]);
        if (!preg_match('/^([a-z]{2,3})(?:[-_]([a-zA-Z]{2,4}))?$/', $candidate, $m)) {
            continue;
        }

        $i18nDir = imscp_elfinder_upstream_dir() . '/js/i18n';
        foreach (isset($m[2]) ? [$m[1] . '_' . strtoupper($m[2]), $m[1]] : [$m[1]] as $code) {
            if ($code === 'en' || is_file($i18nDir . '/elfinder.' . $code . '.js')) {
                $lang = $code;
                break 2;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="<?= App::e(str_replace('_', '-', $lang)) ?>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>File manager - <?= App::e($identity['user']) ?></title>
    <link rel="stylesheet" href="ui/jquery/jquery-ui.min.css">
    <link rel="stylesheet" href="ui/css/elfinder.min.css">
    <link rel="stylesheet" href="ui/css/theme.css">
    <link rel="stylesheet" href="assets/imscp-elfinder.css">
    <script src="ui/jquery/jquery.min.js"></script>
    <script src="ui/jquery/jquery-ui.min.js"></script>
    <script src="ui/js/elfinder.min.js"></script>
    <?php if ($lang !== 'en'): ?>
    <script src="ui/js/i18n/elfinder.<?= App::e($lang) ?>.js"></script>
    <?php endif ?>
    <script src="assets/imscp-elfinder.js"></script>
</head>
<body class="manager">
<header id="imscp-header">
    <span class="title">File manager</span>
    <span class="user"><?= App::e($identity['user']) ?></span>
    <form method="post" action="<?= App::e($basePath) ?>">
        <input type="hidden" name="action" value="logout">
        <input type="hidden" name="csrf_token" value="<?= App::e($csrfToken) ?>">
        <button type="submit">Log out</button>
    </form>
</header>
<div id="elfinder" data-connector="connector.php" data-base-url="ui/" data-lang="<?= App::e($lang) ?>"></div>
</body>
</html>
