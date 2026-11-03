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
 * elFinder connector
 *
 * Only reachable with an authenticated session. The only mounted volume is
 * the FTP volume of the authenticated FTP user (local FTP server).
 */

declare(strict_types=1);

require_once __DIR__ . '/../library/bootstrap.php';

use iMSCP\ElFinder\App;

$app = imscp_elfinder_app();

// elFinder converts PATH_INFO into command arguments
unset($_SERVER['PATH_INFO'], $_SERVER['ORIG_PATH_INFO']);

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate');
// Files served by the connector (cmd=file) are user content: they must never
// be able to run scripts in the origin of the control panel.
header(
    "Content-Security-Policy: sandbox; default-src 'none'; img-src 'self' data: blob:; "
    . "media-src 'self' blob:; style-src 'unsafe-inline'; frame-ancestors 'self'"
);

try {
    $app->startSession();
} catch (\Throwable $e) {
    error_log('i-MSCP elFinder: ' . $e->getMessage());
    http_response_code(503);
    exit;
}

$identity = $app->getIdentity(true);

if (NULL === $identity) {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }

    http_response_code(401);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => ['errAccess'], 'imscpLoginRequired' => true]);
    exit;
}

$upstreamDir = imscp_elfinder_upstream_dir();
if (!is_file($upstreamDir . '/php/autoload.php')) {
    error_log('i-MSCP elFinder: elFinder is not installed');
    http_response_code(503);
    exit;
}

require_once $upstreamDir . '/php/autoload.php';
require_once __DIR__ . '/../library/elFinderImscp.class.php';
require_once __DIR__ . '/../library/elFinderVolumeImscpFTP.class.php';

// No network volume drivers
elFinder::$netDrivers = [];

$workDir = $identity['workdir'];

// Names accepted for new files and directories: no control characters, no
// slashes or backslashes, not '.' or '..' (dot files such as .htaccess are
// allowed, as with any FTP client)
$acceptedName = '#^(?!\.\.?$)[^\x00-\x1f\x7f/\\\\]+$#';

$opts = [
    'debug'               => false,
    'session'             => new elFinderSession([
        'base64encode' => false,
        'keys'         => [
            'default'   => 'elFinderCaches',
            'netvolume' => 'elFinderNetVolumes'
        ],
        'cookieParams' => $app->getCookieParams()
    ]),
    'commonTempPath'      => $workDir,
    'connectionFlagsPath' => $workDir,
    'uploadTempPath'      => $workDir,
    'maxTargets'          => 1000,
    'archivers'           => ['create' => [], 'extract' => []],
    'optionsNetVolumes'   => [],
    'roots'               => [
        [
            'driver'          => 'ImscpFTP',
            'host'            => (string)$app->getConfig('ftp_host'),
            'port'            => (int)$app->getConfig('ftp_port'),
            'ssl'             => (bool)$app->getConfig('ftp_ssl'),
            'timeout'         => (int)$app->getConfig('ftp_timeout'),
            'mode'            => 'passive',
            'user'            => $identity['user'],
            'pass'            => $identity['pass'],
            'path'            => '/',
            'alias'           => $identity['user'],
            'owner'           => true,
            'tmpPath'         => $workDir,
            'tmbPath'         => '',
            'imgLib'          => 'gd',
            'mimeDetect'      => 'internal',
            'uploadMaxSize'   => (string)$app->getConfig('upload_max_size'),
            'disabled'        => elFinderImscp::DISABLED_COMMANDS,
            'acceptedName'    => $acceptedName,
            'acceptedDirname' => $acceptedName,
            'archiveMimes'    => [],
            'archivers'       => ['create' => [], 'extract' => []],
            'checkSubfolders' => -1,
            // Don't chmod new directories: the FTP server umask applies
            'dirMode'         => 0
        ]
    ]
];

// Make sure that the FTP password doesn't end up in a backtrace
unset($identity);

$connector = new elFinderConnector(new elFinderImscp($opts));
$connector->run();
