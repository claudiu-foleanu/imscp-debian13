<?php
/**
 * i-MSCP PolicydSPF plugin
 * @copyright 2016-2017 Laurent Declercq <l.declercq@nuxwin.com>
 * @copyright 2016 Ninos Ego <me@ninosego.de>
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

return array(
    // policyd-spf policy service (default: unix:private/policyd-spf)
    //
    // Postfix policy service for the postfix-policyd-spf-python policy server.
    // Must be in the form unix:private/<name>, where <name> is the name of the
    // spawn(8) service added in the Postfix master.cf file.
    'policyd_spf_service'    => 'unix:private/policyd-spf',

    // policyd-spf time limit (default: 3600s)
    //
    // Set as <name>_time_limit in the Postfix main.cf file. Must be greater
    // than the Postfix smtpd_policy_service_max_idle (default 300s) value.
    'policyd_spf_time_limit' => '3600s',

    // Unix user under which the policy server is run (default: policyd-spf)
    //
    // The policyd-spf user is created by the postfix-policyd-spf-python package.
    'policyd_spf_user'       => 'policyd-spf'

    // Note: The SPF policy (HELO_reject, Mail_From_reject, PermError_reject,
    // TempError_Defer, Header_Type, whitelists...) is configured through the
    // /etc/postfix-policyd-spf-python/policyd-spf.conf file. See policyd-spf.conf(5).
);
