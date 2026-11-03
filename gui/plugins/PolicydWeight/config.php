<?php
/**
 * i-MSCP PolicydWeight plugin
 * @copyright 2015-2018 Laurent Declercq <l.declercq@nuxwin.com>
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
    // policyd-weight listening address (default: 127.0.0.1)
    //
    // Written as $BIND_ADDRESS in the /etc/policyd-weight.conf file.
    'policyd_weight_host' => '127.0.0.1',

    // policyd-weight listening port (default: 12525)
    //
    // Written as $TCP_PORT in the /etc/policyd-weight.conf file.
    'policyd_weight_port' => 12525,

    // DNSBL (RBL) list: [ zone, hit score, miss score, log name ]
    //
    // Written as @dnsbl_score in the /etc/policyd-weight.conf file.
    //
    // IMPORTANT: policyd-weight treats ANY answer as a listing. DNSBLs that
    // have been shut down, or that answer with a 'query refused' code when
    // queried through public resolvers (Spamhaus: 127.255.255.x, SURBL:
    // 127.0.0.1), lead to false positives. Make sure that the server uses its
    // own recursive resolver (e.g. the local Bind9 server; nameserver 127.0.0.1
    // in /etc/resolv.conf) and keep this list up to date.
    //
    // Removed from the policyd-weight defaults:
    //  - ix.dnsbl.manitu.net (NiX Spam): shut down in January 2025
    // Never use dead DNSBLs such as SORBS (shut down in 2024), NJABL, AHBL,
    // DSBL, rfc-ignorant.org, which may list the whole Internet.
    'dnsbl_score'         => array(
        array('pbl.spamhaus.org', 3.25, 0, 'DYN_PBL_SPAMHAUS'),
        array('sbl-xbl.spamhaus.org', 4.35, -1.5, 'SBL_XBL_SPAMHAUS'),
        array('bl.spamcop.net', 3.75, -1.5, 'SPAMCOP'),
        array('psbl.surriel.com', 2.5, 0, 'PSBL')
    ),

    // RHSBL list (sender domain): [ zone, hit score, miss score, log name ]
    //
    // Written as @rhsbl_score in the /etc/policyd-weight.conf file.
    'rhsbl_score'         => array(
        array('multi.surbl.org', 4, 0, 'SURBL')
    )
);
