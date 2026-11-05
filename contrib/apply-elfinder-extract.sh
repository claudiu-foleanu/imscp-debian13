#!/bin/sh
# apply-elfinder-extract.sh
#
# Enable ZIP extraction in the i-MSCP elFinder file manager on a RUNNING
# machine, in place (no reinstall, no git checkout needed).
#
# ZIP only, via PHP's ZipArchive class -- no shell archiver is ever executed,
# archive creation stays disabled. Safe only on elFinder 2.1.70+, which fixes
# CVE-2026-81891 (ZIP-extraction MIME bypass); the script refuses to run
# otherwise.
#
# Idempotent: re-running it just re-applies the same files. A timestamped
# backup of every replaced file is kept.
set -eu

DST=/var/www/imscp/gui/vendor/imscp/elfinder
SRC=/var/www/imscp/gui/composer/imscp-elfinder   # deployed source copy (kept in sync)
PANEL_USER=vu2000
TS=$(date +%Y%m%d%H%M%S)
BACKUP="/root/elfinder-extract-backup-$TS"

[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
[ -d "$DST/library" ] || { echo "elFinder not found at $DST" >&2; exit 1; }

# --- 2.1.70+ guard -----------------------------------------------------------
JS="$DST/elfinder/js/elfinder.min.js"
if ! grep -qE "Version 2\.1\.(7[0-9]|[89][0-9]|[0-9]{3,})" "$JS" 2>/dev/null; then
    echo "Refusing: elFinder is not >= 2.1.70 (CVE-2026-81891 unfixed). Update i-MSCP first." >&2
    exit 1
fi

mkdir -p "$BACKUP/library" "$BACKUP/public"
for f in library/elFinderImscp.class.php library/elFinderVolumeImscpFTP.class.php public/connector.php; do
    [ -f "$DST/$f" ] && cp -a "$DST/$f" "$BACKUP/$f"
done
echo "Backup of replaced files: $BACKUP"

write() {  # write() <relative-path> ; content on stdin
    rel="$1"
    for dir in "$DST" "$SRC"; do
        [ -d "$dir/$(dirname "$rel")" ] || continue
        cat > "$dir/$rel"
        return 0 2>/dev/null || true
    done
}

# ---- library/elFinderImscp.class.php ----
for dir in "$DST" "$SRC"; do [ -d "$dir/library" ] && cat > "$dir/library/elFinderImscp.class.php" <<'EOF_IMSCP'
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
 * elFinder restricted to an allowlist of commands
 *
 * Commands that are not in the allowlist (netmount, archive, resize,
 * zipdl, editor, callback, url, tmb, dim...) are reported as unknown commands
 * by both the connector and elFinder::exec().
 *
 * 'extract' is allowed (ZIP archives only, extracted through PHP's ZipArchive
 * class -- no shell command is ever executed, see elFinderVolumeImscpFTP).
 */
class elFinderImscp extends elFinder
{
    /**
     * Allowed commands
     *
     * @var array
     */
    const ALLOWED_COMMANDS = array(
        'abort', 'chmod', 'duplicate', 'extract', 'file', 'get', 'info', 'ls',
        'mkdir', 'mkfile', 'open', 'parents', 'paste', 'put', 'rename', 'rm',
        'search', 'size', 'subdirs', 'tree', 'upload'
    );

    /**
     * Commands disabled in the client
     *
     * @var array
     */
    const DISABLED_COMMANDS = array(
        'archive', 'callback', 'dim', 'editor', 'netmount',
        'resize', 'tmb', 'url', 'zipdl'
    );

    /**
     * @inheritdoc
     */
    public function commandExists($cmd)
    {
        return is_string($cmd)
            && in_array($cmd, self::ALLOWED_COMMANDS, true)
            && parent::commandExists($cmd);
    }

    /**
     * @inheritdoc
     */
    public function exec($cmd, $args)
    {
        // Uploads from URLs or data URIs (server-side fetch) are not allowed.
        // The 'upload' parameter is only accepted for chunked upload commits
        // (in which case elFinder never fetches URLs).
        if ($cmd === 'upload' && !empty($args['upload']) && empty($args['chunk'])) {
            return array('error' => $this->error(elFinder::ERROR_PERM_DENIED));
        }

        return parent::exec($cmd, $args);
    }
}
EOF_IMSCP
done

# ---- library/elFinderVolumeImscpFTP.class.php ----
for dir in "$DST" "$SRC"; do [ -d "$dir/library" ] && cat > "$dir/library/elFinderVolumeImscpFTP.class.php" <<'EOF_FTPVOL'
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
 * elFinder FTP volume driver hardened for i-MSCP
 *
 * - Never executes shell commands (procExec() is disabled: no shell archivers,
 *   no ImageMagick CLI...). ZIP extraction is supported through PHP's
 *   ZipArchive class only; creating archives remains disabled.
 * - Always uses the authenticated FTP control connection for transfers (the
 *   upstream driver can open a second connection through the ftp:// stream
 *   wrapper, putting the credentials in an URL).
 * - Always uses binary transfer mode (ASCII mode alters line endings, and
 *   VsFTPd ignores it by default).
 * - Ignores the IP address returned in PASV responses (the FTP server can be
 *   configured to masquerade its public IP address): data connections are
 *   always made to the host of the control connection (loopback).
 */
class elFinderVolumeImscpFTP extends elFinderVolumeFTP
{
    /**
     * @inheritdoc
     */
    protected $driverId = 'i';

    /**
     * @inheritdoc
     */
    protected function connect()
    {
        if (!parent::connect()) {
            return false;
        }

        if (defined('FTP_USEPASVADDRESS')) {
            @ftp_set_option($this->connect, FTP_USEPASVADDRESS, false);
        }

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function ftpMode($path)
    {
        return FTP_BINARY;
    }

    /**
     * @inheritdoc
     */
    protected function _fopen($path, $mode = 'rb')
    {
        if (!$this->tmp) {
            return false;
        }

        $local = $this->getTempFile($path);
        if (($fp = fopen($local, 'wb')) === false) {
            return false;
        }

        $ret = ftp_nb_fget($this->connect, $fp, $path, FTP_BINARY);
        while ($ret === FTP_MOREDATA) {
            elFinder::extendTimeLimit();
            $ret = ftp_nb_continue($this->connect);
        }

        fclose($fp);

        if ($ret === FTP_FINISHED) {
            return fopen($local, $mode);
        }

        is_file($local) && unlink($local);
        return false;
    }

    /**
     * @inheritdoc
     */
    protected function procExec($command, &$output = '', &$return_var = -1, &$error_output = '', $cwd = null)
    {
        $output = '';
        $error_output = 'Disabled';
        $return_var = -1;
        return -1;
    }

    /**
     * @inheritdoc
     *
     * Keep extraction only, and only PHP-based ('phpfunction') archivers, so
     * that procExec() (disabled above) is never relied upon. In practice this
     * exposes ZIP extraction via PHP's ZipArchive class. Creating archives
     * stays disabled (empty 'create'). $use_cache is forced off so the empty
     * 'archivers' connector option does not short-circuit detection.
     */
    protected function getArchivers($use_cache = true)
    {
        $archivers = parent::getArchivers(false);

        $extract = array();
        if (isset($archivers['extract']) && is_array($archivers['extract'])) {
            foreach ($archivers['extract'] as $mime => $conf) {
                if (isset($conf['cmd']) && $conf['cmd'] === 'phpfunction') {
                    $extract[$mime] = $conf;
                }
            }
        }

        return array('create' => array(), 'extract' => $extract);
    }

    /**
     * @inheritdoc
     *
     * Creating archives is not supported (no shell, create archivers disabled).
     */
    protected function _archive($dir, $files, $name, $arc)
    {
        return false;
    }
}
EOF_FTPVOL
done

# ---- public/connector.php ----
for dir in "$DST" "$SRC"; do [ -d "$dir/public" ] && cat > "$dir/public/connector.php" <<'EOF_CONN'
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
            // Safety ceiling on the total extracted size of an archive. The
            // work directory lives on the (shared) panel server, so this bounds
            // how much an extraction may write there. Generous enough for real
            // archives while rejecting pathological ones.
            'maxArcFilesSize' => '2G',
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
EOF_CONN
done

# --- ownership + opcache -----------------------------------------------------
chown -R "$PANEL_USER:$PANEL_USER" "$DST/library" "$DST/public" 2>/dev/null || true
[ -d "$SRC/library" ] && chown -R "$PANEL_USER:$PANEL_USER" "$SRC/library" "$SRC/public" 2>/dev/null || true

# syntax-check the three files before restarting
for f in "$DST/library/elFinderImscp.class.php" "$DST/library/elFinderVolumeImscpFTP.class.php" "$DST/public/connector.php"; do
    php -l "$f" >/dev/null || { echo "Syntax check failed for $f -- restoring backup." >&2; cp -a "$BACKUP/"* "$DST/" 2>/dev/null; exit 1; }
done

systemctl restart imscp_panel 2>/dev/null || service imscp_panel restart 2>/dev/null || true

echo "Done. ZIP extraction is enabled. Test: panel -> File Manager -> upload a .zip -> Extract (use a fresh login)."
echo "To revert: copy files from $BACKUP back into $DST and restart imscp_panel."
