<?php
/**
 * i-MSCP - internet Multi Server Control Panel
 * Copyright (C) 2010-2019 by Laurent Declercq <l.declercq@nuxwin.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * Register and schedule installation of the plugins bundled with the
 * distribution.
 *
 * This reproduces, non-interactively, what an administrator would do through
 * the panel (System Tools -> Plugin Management): synchronize the plugin data
 * (register plugins found on disk) and then install+enable each bundled plugin.
 *
 * The backend part of each plugin is scheduled (status 'toinstall'/'toenable')
 * and applied by the DB tasks processor that the installer runs right after
 * this script.
 *
 * The script is idempotent and best-effort: plugins that are already enabled
 * are left untouched, and any per-plugin failure is reported but never aborts
 * the installation.
 */

/** @noinspection PhpIncludeInspection */

define('IMSCP_SETUP', true);

use iMSCP\Registry;

try {
    chdir(dirname(__FILE__));
    require_once '../../gui/include/imscp-lib.php';

    /** @var \iMSCP\Plugin\PluginManager $pm */
    $pm = Registry::get('pluginManager');

    // Register plugins present on disk (equivalent to the "Update Plugins"
    // button). Harmless when there is nothing new to register.
    try {
        $pm->pluginSyncData();
    } catch (Throwable $e) {
        fwrite(STDERR, sprintf(
            "[WARN] Plugin synchronization failed: %s\n", $e->getMessage()
        ));
    }

    $installed = 0;
    $enabled = 0;
    $skipped = 0;
    $failed = 0;

    foreach (array_values($pm->pluginGetList(false)) as $name) {
        try {
            // Already active: leave it to the regular 'tochange' reconcile.
            if ($pm->pluginIsEnabled($name)) {
                $skipped++;
                continue;
            }

            $status = $pm->pluginGetStatus($name);

            if (in_array($status, ['uninstalled', 'toinstall'], true)
                && $pm->pluginIsInstallable($name)
            ) {
                // Installs the plugin (frontend part) and schedules its
                // backend install + enable.
                $pm->pluginInstall($name);
                $installed++;
            } elseif ($pm->pluginIsDisabled($name)) {
                $pm->pluginEnable($name);
                $enabled++;
            } else {
                $skipped++;
            }
        } catch (Throwable $e) {
            $failed++;
            fwrite(STDERR, sprintf(
                "[WARN] Plugin '%s' could not be deployed: %s\n",
                $name,
                $e->getMessage()
            ));
        }
    }

    fwrite(STDOUT, sprintf(
        "Bundled plugins: %d scheduled for installation, %d enabled, %d skipped, %d failed\n",
        $installed,
        $enabled,
        $skipped,
        $failed
    ));

    // Best-effort step: never abort the installer because of plugins.
    exit(0);
} catch (Throwable $e) {
    fwrite(STDERR, sprintf(
        "[WARN] Bundled plugin deployment was skipped: %s\n", $e->getMessage()
    ));
    // Do not break the installation when the plugin subsystem is unavailable.
    exit(0);
}
