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

declare(strict_types=1);

namespace iMSCP\ElFinder;

use RuntimeException;

/**
 * i-MSCP elFinder front-end
 *
 * Authenticates customers against the local FTP server and keeps the FTP
 * credentials server-side, in the PHP session (the password being encrypted
 * with a key that is not stored in the session).
 */
final class App
{
    /** @var string Session name */
    const SESSION_NAME = 'IMSCP_ELFINDER';

    /** @var string Session key holding authentication data */
    const SESSION_KEY = 'imscp_elfinder';

    /** @var array Configuration */
    private $config;

    /** @var string Base URL path (with trailing slash) */
    private $basePath;

    /**
     * Constructor
     *
     * @param array $config Configuration
     */
    public function __construct(array $config)
    {
        $this->config = $config + [
                'ftp_host'           => '127.0.0.1',
                'ftp_port'           => 21,
                'ftp_ssl'            => false,
                'ftp_timeout'        => 15,
                'tmp_dir'            => '',
                'secret_key'         => '',
                'idle_timeout'       => 1800,
                'max_lifetime'       => 28800,
                'max_login_failures' => 10,
                'login_window'       => 900,
                'upload_max_size'    => '128M',
                'timezone'           => 'UTC'
            ];

        if (!preg_match('/^[0-9a-f]{64}$/', (string)$this->config['secret_key'])) {
            throw new RuntimeException('Invalid secret key.');
        }

        if (!strlen($this->config['tmp_dir']) || !is_dir($this->config['tmp_dir'])) {
            throw new RuntimeException('Invalid temporary directory.');
        }

        $this->config['tmp_dir'] = rtrim($this->config['tmp_dir'], '/');

        @date_default_timezone_set($this->config['timezone']) || date_default_timezone_set('UTC');

        $scriptName = isset($_SERVER['SCRIPT_NAME']) ? (string)$_SERVER['SCRIPT_NAME'] : '/';
        $this->basePath = rtrim(str_replace('\\', '/', dirname($scriptName)), '/') . '/';
    }

    /**
     * Get configuration value
     *
     * @param string $name
     * @return mixed
     */
    public function getConfig(string $name)
    {
        return $this->config[$name] ?? NULL;
    }

    /**
     * Get base URL path
     *
     * @return string
     */
    public function getBasePath(): string
    {
        return $this->basePath;
    }

    /**
     * Is the current request made over HTTPS?
     *
     * @return bool
     */
    public static function isSecureRequest(): bool
    {
        return !empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off';
    }

    /**
     * Get session cookie parameters
     *
     * @return array
     */
    public function getCookieParams(): array
    {
        return [
            'lifetime' => 0,
            'path'     => $this->basePath,
            'domain'   => '',
            'secure'   => self::isSecureRequest(),
            'httponly' => true,
            'samesite' => 'Strict'
        ];
    }

    /**
     * Get private working directory
     *
     * @param string $name Directory name
     * @return string
     */
    public function getPrivateDir(string $name): string
    {
        $dir = $this->config['tmp_dir'] . '/' . $name;

        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException(sprintf("Couldn't create the %s directory.", $dir));
        }

        return $dir;
    }

    /**
     * Start the PHP session
     *
     * @return void
     */
    public function startSession()
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        $gcLifetime = max((int)$this->config['idle_timeout'], 300) + 300;

        ini_set('session.save_handler', 'files');
        ini_set('session.save_path', $this->getPrivateDir('sessions'));
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_cookies', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.cache_limiter', 'nocache');
        ini_set('session.sid_length', '48');
        ini_set('session.sid_bits_per_character', '6');
        ini_set('session.gc_maxlifetime', (string)$gcLifetime);
        ini_set('session.gc_probability', '1');
        ini_set('session.gc_divisor', '100');
        ini_set('session.lazy_write', '1');
        session_name(self::SESSION_NAME);
        session_set_cookie_params($this->getCookieParams());

        if (!session_start()) {
            throw new RuntimeException("Couldn't start session.");
        }
    }

    /**
     * Return authentication data if the user is authenticated
     *
     * Also enforces the idle timeout and the maximum session lifetime. Expired
     * sessions are destroyed.
     *
     * @param bool $touch Whether the last activity time must be updated
     * @return array|null Array containing the 'user' and 'pass' keys, NULL if the user is not authenticated
     */
    public function getIdentity(bool $touch = true)
    {
        if (!isset($_SESSION[self::SESSION_KEY]['user'], $_SESSION[self::SESSION_KEY]['pass'])) {
            return NULL;
        }

        $auth =& $_SESSION[self::SESSION_KEY];
        $now = time();

        if ($now - (int)$auth['last_activity'] > (int)$this->config['idle_timeout']
            || $now - (int)$auth['login_time'] > (int)$this->config['max_lifetime']
            || !isset($auth['ua']) || !hash_equals($auth['ua'], $this->getUserAgentHash())
        ) {
            $this->logout();
            return NULL;
        }

        $password = $this->decrypt((string)$auth['pass']);
        if ($password === NULL) {
            $this->logout();
            return NULL;
        }

        if ($touch) {
            $auth['last_activity'] = $now;
        }

        return [
            'user'    => (string)$auth['user'],
            'pass'    => $password,
            'workdir' => $this->getPrivateDir('work/' . $auth['work_key'])
        ];
    }

    /**
     * Get CSRF token for HTML forms
     *
     * @return string
     */
    public function getCsrfToken(): string
    {
        if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }

        return $_SESSION['csrf_token'];
    }

    /**
     * Check CSRF token from HTML forms
     *
     * @param mixed $token
     * @return bool
     */
    public function checkCsrfToken($token): bool
    {
        return is_string($token)
            && !empty($_SESSION['csrf_token'])
            && is_string($_SESSION['csrf_token'])
            && hash_equals($_SESSION['csrf_token'], $token);
    }

    /**
     * Process login
     *
     * @param mixed $username
     * @param mixed $password
     * @return bool TRUE on success, FALSE on failure
     */
    public function login($username, $password): bool
    {
        // Per-session delay (in addition to the per-IP rate limit)
        $sessionFailures = (int)($_SESSION['login_failures'] ?? 0);

        if (!$this->checkRateLimit()) {
            sleep(min(2 + $sessionFailures, 10));
            return false;
        }

        $ok = is_string($username) && is_string($password)
            && strlen($username) > 0 && strlen($username) <= 255
            && strlen($password) > 0 && strlen($password) <= 1024
            // No control characters (would allow FTP command injection)
            && !preg_match('/[\x00-\x1f\x7f]/', $username . $password)
            && $this->checkFtpCredentials($username, $password);

        if (!$ok) {
            $this->registerLoginFailure();
            $_SESSION['login_failures'] = $sessionFailures + 1;
            sleep(min(2 + $sessionFailures, 10));
            return false;
        }

        $this->resetRateLimit();
        session_regenerate_id(true);

        $now = time();
        $_SESSION = [
            self::SESSION_KEY => [
                'user'          => $username,
                'pass'          => $this->encrypt($password),
                'login_time'    => $now,
                'last_activity' => $now,
                'ua'            => $this->getUserAgentHash(),
                'work_key'      => bin2hex(random_bytes(16))
            ],
            // New CSRF token for the authenticated session
            'csrf_token'    => bin2hex(random_bytes(32))
        ];

        $this->cleanupStaleWorkDirs();
        return true;
    }

    /**
     * Logout (destroy the session and its private working directory)
     *
     * @return void
     */
    public function logout()
    {
        if (isset($_SESSION[self::SESSION_KEY]['work_key'])
            && preg_match('/^[0-9a-f]{32}$/', (string)$_SESSION[self::SESSION_KEY]['work_key'])
        ) {
            self::removeDir($this->config['tmp_dir'] . '/work/' . $_SESSION[self::SESSION_KEY]['work_key']);
        }

        $_SESSION = [];

        if (session_status() === PHP_SESSION_ACTIVE) {
            if (!headers_sent()) {
                $params = $this->getCookieParams();
                $params['expires'] = time() - 86400;
                unset($params['lifetime']);
                setcookie(session_name(), '', $params);
            }

            session_destroy();
        }
    }

    /**
     * Check FTP credentials by logging into the local FTP server
     *
     * @param string $username
     * @param string $password
     * @return bool
     */
    private function checkFtpCredentials(string $username, string $password): bool
    {
        $conn = $this->config['ftp_ssl']
            ? @ftp_ssl_connect($this->config['ftp_host'], (int)$this->config['ftp_port'], (int)$this->config['ftp_timeout'])
            : @ftp_connect($this->config['ftp_host'], (int)$this->config['ftp_port'], (int)$this->config['ftp_timeout']);

        if ($conn === false) {
            error_log('i-MSCP elFinder: Could not connect to the FTP server');
            return false;
        }

        $ret = @ftp_login($conn, $username, $password);
        @ftp_close($conn);

        if (!$ret) {
            error_log(sprintf(
                'i-MSCP elFinder: Failed login for FTP user %s from %s',
                preg_replace('/[^\x20-\x7e]/', '?', $username),
                $this->getClientIp()
            ));
        }

        return (bool)$ret;
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function getClientIp(): string
    {
        return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : 'unknown';
    }

    /**
     * Get hash of the client user agent
     *
     * @return string
     */
    private function getUserAgentHash(): string
    {
        return hash('sha256', isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '');
    }

    /**
     * Get rate limit file path for the client IP address
     *
     * @return string
     */
    private function getRateLimitFile(): string
    {
        return $this->getPrivateDir('ratelimit') . '/' . hash_hmac('sha256', $this->getClientIp(), $this->config['secret_key']);
    }

    /**
     * Read and update rate limit data for the client IP address
     *
     * @param callable $callback Callback receiving and returning the data
     * @return array Data
     */
    private function rateLimitData(callable $callback): array
    {
        $file = $this->getRateLimitFile();
        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            return $callback(['failures' => 0, 'first' => time()]);
        }

        flock($fh, LOCK_EX);
        $data = json_decode((string)stream_get_contents($fh), true);
        if (!is_array($data) || !isset($data['failures'], $data['first'])
            || time() - (int)$data['first'] > (int)$this->config['login_window']
        ) {
            $data = ['failures' => 0, 'first' => time()];
        }

        $data = $callback($data);
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, json_encode($data));
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);

        return $data;
    }

    /**
     * Whether the client IP address is allowed to try to login
     *
     * @return bool
     */
    private function checkRateLimit(): bool
    {
        $data = $this->rateLimitData(function (array $data) {
            return $data;
        });

        return (int)$data['failures'] < (int)$this->config['max_login_failures'];
    }

    /**
     * Register a login failure for the client IP address
     *
     * @return void
     */
    private function registerLoginFailure()
    {
        $this->rateLimitData(function (array $data) {
            $data['failures'] = (int)$data['failures'] + 1;
            return $data;
        });
    }

    /**
     * Reset login failures for the client IP address
     *
     * @return void
     */
    private function resetRateLimit()
    {
        @unlink($this->getRateLimitFile());
    }

    /**
     * Remove stale private working directories and rate limit files
     *
     * @return void
     */
    private function cleanupStaleWorkDirs()
    {
        $maxAge = max((int)$this->config['max_lifetime'], (int)$this->config['idle_timeout']) + 3600;

        foreach ((array)glob($this->getPrivateDir('work') . '/*', GLOB_ONLYDIR | GLOB_NOSORT) as $dir) {
            if (preg_match('#/[0-9a-f]{32}$#', $dir) && @filemtime($dir) < time() - $maxAge) {
                self::removeDir($dir);
            }
        }

        foreach ((array)glob($this->getPrivateDir('ratelimit') . '/*', GLOB_NOSORT) as $file) {
            if (@filemtime($file) < time() - (int)$this->config['login_window'] - 60) {
                @unlink($file);
            }
        }
    }

    /**
     * Remove a directory recursively (symlinks are not followed)
     *
     * @param string $dir
     * @return void
     */
    public static function removeDir(string $dir)
    {
        if (is_link($dir) || !is_dir($dir)) {
            @unlink($dir);
            return;
        }

        foreach ((array)scandir($dir) as $entry) {
            if ($entry === '.' || $entry === '..' || $entry === false) {
                continue;
            }

            $path = $dir . '/' . $entry;
            if (!is_link($path) && is_dir($path)) {
                self::removeDir($path);
            } else {
                @unlink($path);
            }
        }

        @rmdir($dir);
    }

    /**
     * Encrypt the given data
     *
     * @param string $data
     * @return string
     */
    private function encrypt(string $data): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce . sodium_crypto_secretbox($data, $nonce, $this->getKey()));
    }

    /**
     * Decrypt the given data
     *
     * @param string $data
     * @return string|null Decrypted data, NULL on failure
     */
    private function decrypt(string $data)
    {
        $data = base64_decode($data, true);
        if ($data === false || strlen($data) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return NULL;
        }

        $plain = sodium_crypto_secretbox_open(
            substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $this->getKey()
        );

        return $plain === false ? NULL : $plain;
    }

    /**
     * Get encryption key
     *
     * @return string
     */
    private function getKey(): string
    {
        return hash_hmac('sha256', 'session-encryption', hex2bin($this->config['secret_key']), true);
    }

    /**
     * Send common security headers
     *
     * @return void
     */
    public static function sendSecurityHeaders()
    {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        header(
            "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            . "img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self' data:; connect-src 'self'; "
            . "worker-src 'self' blob:; frame-src 'self' blob:; object-src 'none'; base-uri 'none'; "
            . "form-action 'self'; frame-ancestors 'none'"
        );
    }

    /**
     * Escape a string for use in HTML
     *
     * @param string $string
     * @return string
     */
    public static function e(string $string): string
    {
        return htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
