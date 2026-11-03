<?php
/**
 * i-MSCP OpenDMARC plugin
 * Copyright (C) 2026 i-MSCP Debian 13 port
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

use iMSCP_Config_Handler_File as ConfigFile;
use iMSCP_Registry as Registry;

$postfixConfig = new ConfigFile(Registry::get('config')['CONF_DIR'] . '/postfix/postfix.data');

return [
    ////////////////////////////////////////////////////////////////////////////
    // Outbound policy: _dmarc.<domain> TXT records (RFC 7489)
    //
    // A record is published for every customer domain and domain alias.
    // Subdomains are covered by the organizational domain record (see the
    // 'sp' tag below) and get no record of their own.
    //
    // Values below are the server-wide defaults. Customers can override them
    // per domain (Domains -> DMARC) unless 'customer_can_edit' is false.
    // Changing a default re-renders all records that don't override it.
    ////////////////////////////////////////////////////////////////////////////

    // Default policy (p=) (default: none)
    //
    // Possible values: none, quarantine, reject
    //
    // Start with 'none' (monitoring only). Only move to quarantine/reject once
    // SPF and DKIM (OpenDKIM plugin) are in place for the domain, otherwise
    // legitimate mail from the domain will be junked or rejected by receivers.
    'dmarc_policy'            => 'none',

    // Default subdomain policy (sp=) (default: '' - tag omitted, receivers
    // apply the 'p' policy to subdomains)
    //
    // Possible values: '', none, quarantine, reject
    'dmarc_subdomain_policy'  => '',

    // Default percentage of messages to which the policy applies (pct=)
    // (default: 100 - tag omitted)
    //
    // Possible values: integer 1..100
    'dmarc_pct'               => 100,

    // Default DKIM / SPF identifier alignment mode (adkim= / aspf=)
    // (default: r)
    //
    // Possible values: r (relaxed), s (strict)
    'dmarc_adkim'             => 'r',
    'dmarc_aspf'              => 'r',

    // Default aggregate (rua=) and failure (ruf=) report addresses
    // (default: '' - no reports requested)
    //
    // A single e-mail address (without the mailto: prefix). If the address
    // domain differs from the policy domain, the receiving domain must
    // authorize it (RFC 7489 section 7.1):
    //   <policy-domain>._report._dmarc.<report-domain> IN TXT "v=DMARC1"
    'dmarc_rua'               => '',
    'dmarc_ruf'               => '',

    // TTL of the _dmarc DNS records (default: 3600)
    //
    // Possible value: time in seconds (60..86400)
    'dmarc_dns_records_ttl'   => 3600,

    // Whether customers can override the defaults above for their domains
    // (default: true). When false, the customer page is read-only.
    'customer_can_edit'       => true,

    ////////////////////////////////////////////////////////////////////////////
    // Inbound verification: OpenDMARC milter
    ////////////////////////////////////////////////////////////////////////////

    // Reject messages failing DMARC evaluation when the sender domain policy
    // is p=reject (default: false)
    //
    // false: messages are never rejected; an Authentication-Results header
    //        field carrying the DMARC result is added (to be used by
    //        SpamAssassin / Sieve filters).
    // true : messages failing DMARC from domains publishing p=reject are
    //        rejected (5xx) and messages that couldn't be evaluated
    //        (e.g. DNS timeout) are temp-failed (4xx).
    'opendmarc_reject_failures' => false,

    // Authserv-id (default: i-MSCP server hostname)
    //
    // Used in the Authentication-Results header fields added by OpenDMARC.
    // It is also trusted (TrustedAuthservIDs) together with the Postfix
    // myhostname value, which OpenDKIM uses for its own A-R header field.
    'opendmarc_authserv_id'   => Registry::get('config')['SERVER_HOSTNAME'],

    // Additional trusted authserv-ids (default: none)
    //
    // Authentication-Results header fields bearing one of these authserv-ids
    // are trusted as DKIM input for the DMARC evaluation. Only list hosts
    // under your control.
    'opendmarc_trusted_authserv_ids' => [],

    // Additional hosts whose SMTP connections are not evaluated (default: none)
    //
    // 127.0.0.1, ::1 and the Postfix mynetworks entries are always ignored
    // (outgoing mail). Hostnames, IP addresses and CIDR blocks are allowed.
    'opendmarc_ignore_hosts'  => [],

    // OpenDMARC socket (default: local:<POSTFIX_QUEUE_DIR>/opendmarc/opendmarc.sock)
    //
    // The Postfix smtpd(8) service is chrooted, hence the UNIX socket must be
    // created inside the Postfix queue directory.
    //
    // Related parameter: postfix_milter_socket
    'opendmarc_socket'        => "local:{$postfixConfig['POSTFIX_QUEUE_DIR']}/opendmarc/opendmarc.sock",

    // OpenDMARC user and group (default: opendmarc)
    'opendmarc_user'          => 'opendmarc',
    'opendmarc_group'         => 'opendmarc',

    // Postfix milter socket for OpenDMARC (default: unix:/opendmarc/opendmarc.sock)
    //
    // Path of the OpenDMARC socket, relative to the Postfix queue directory.
    'postfix_milter_socket'   => 'unix:/opendmarc/opendmarc.sock',

    // Postfix per-milter default action for OpenDMARC (default: accept)
    //
    // Action taken by Postfix when the OpenDMARC milter is unavailable. Keep
    // 'accept' so that mail is never blocked because of the DMARC milter.
    //
    // Possible values: accept, reject, tempfail, quarantine
    'postfix_milter_default_action' => 'accept'
];
