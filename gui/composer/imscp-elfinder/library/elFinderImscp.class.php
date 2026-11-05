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
