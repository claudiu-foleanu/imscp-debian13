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
 * - Never executes shell commands (no archivers, no ImageMagick CLI...).
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
     */
    protected function getArchivers($use_cache = true)
    {
        return array('create' => array(), 'extract' => array());
    }

    /**
     * @inheritdoc
     */
    protected function _archive($dir, $files, $name, $arc)
    {
        return false;
    }

    /**
     * @inheritdoc
     */
    protected function _extract($path, $arc)
    {
        return false;
    }
}
