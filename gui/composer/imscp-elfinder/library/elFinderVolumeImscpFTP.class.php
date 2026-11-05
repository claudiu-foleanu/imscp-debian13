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
     * that procExec() (disabled above) is never relied upon. This exposes ZIP
     * extraction via PHP's ZipArchive class and, additionally, TAR-family
     * extraction (.tar, .tar.gz/.tgz, .tar.bz2/.tbz) via PHP's PharData class.
     * Creating archives stays disabled (empty 'create'). $use_cache is forced
     * off so the empty 'archivers' connector option does not short-circuit
     * detection.
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

        // TAR family through PHP's PharData (no shell). PharData detects the
        // compression from the archive extension, which the FTP extractor
        // preserves in the temporary file.
        if (class_exists('PharData', false)) {
            $phar = array(
                'cmd'  => 'phpfunction',
                'argc' => array('elFinderVolumeImscpFTP', 'pharExtract')
            );
            $extract['application/x-tar']   = $phar + array('ext' => 'tar');
            $extract['application/x-gzip']  = $phar + array('ext' => 'tgz');
            $extract['application/x-bzip2'] = $phar + array('ext' => 'tbz');
        }

        return array('create' => array(), 'extract' => $extract);
    }

    /**
     * Extract a TAR-family archive (.tar, .tar.gz/.tgz, .tar.bz2/.tbz) using
     * PHP's PharData class -- no shell command is executed.
     *
     * Registered as a 'phpfunction' archiver, so elFinder calls it as
     * pharExtract($archivePath, $destDir). Must be public static for
     * call_user_func_array() in elFinderVolumeDriver::unpackArchive().
     *
     * @param string $path  Path to the (already downloaded) archive
     * @param string $toDir Destination directory
     * @return void
     * @throws Exception on error (handled by elFinder like the ZIP extractor)
     */
    public static function pharExtract($path, $toDir)
    {
        try {
            $arc = new PharData($path);

            // Reject archives whose extracted size exceeds the configured
            // ceiling, before writing anything to disk.
            $maxSize = empty(self::$maxArcFilesSize) ? 0 : (int)self::$maxArcFilesSize;
            if ($maxSize > 0) {
                $total = 0;
                foreach (new RecursiveIteratorIterator($arc) as $file) {
                    $total += $file->getSize();
                    if ($total > $maxSize) {
                        throw new Exception(elFinder::ERROR_ARC_MAXSIZE);
                    }
                }
            }

            $arc->extractTo($toDir, null, true);
        } catch (Throwable $e) {
            throw new Exception($e->getMessage());
        }
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
