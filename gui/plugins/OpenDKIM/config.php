<?php
/**
 * i-MSCP OpenDKIM plugin
 * Copyright (C) 2013-2017 Laurent Declercq <l.declercq@nuxwin.com>
 * Copyright (C) 2013-2016 Rene Schuster <mail@reneschuster.de>
 * Copyright (C) 2013-2016 Sascha Bay <info@space2place.de>
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
    // OpenDKIM canonicalization method (default: relaxed/simple)
    //
    // Canonicalization method(s) to be used when signing messages. When
    // verifying, the message's DKIM-Signature header field specifies the
    // canonicalization method.
    //
    // The value may include two different canonicalizations separated by a
    // slash ("/") character, in which case the first will be applied to the
    // header and the second to the body.
    //
    // Possible values: simple, relaxed, simple/relaxed, relaxed/simple or relaxed/relaxed
    'opendkim_canonicalization'     => 'relaxed/simple',

    // OpenDKIM configuration directory (default: /etc/opendkim)
    //
    // Directory holding the KeyTable, SigningTable and TrustedHosts files and
    // the DKIM keys (keys/<domain>/mail.private).
    'opendkim_confdir'              => '/etc/opendkim',

    // OpenDKIM DNS resource records TTL (default: 300)
    //
    // Possible value: Time in seconds
    'opendkim_dns_records_ttl'      => 300,

    // OpenDKIM group (default: opendkim)
    'opendkim_group'                => 'opendkim',

    // OpenDKIM key size (default: 2048)
    //
    // See https://tools.ietf.org/html/rfc8301#section-3.2
    // Minimum key length is 1024 bits. Keys longer than 2048 bits may not be
    // supported by all verifiers and don't fit in a single DNS UDP packet.
    'opendkim_keysize'              => 2048,

    // OpenDKIM action to be taken when a signature fails to validate (default: accept)
    //
    // Possible values: accept, discard, quarantine, reject, tempfail
    //
    // Note: A failed signature must be treated as if the message wasn't signed
    // (RFC 6376 section 6.1). Rejecting would break legitimate mails that went
    // through mailing lists or forwarders.
    'opendkim_on_bad_signature'     => 'accept',

    // OpenDKIM action to be taken when a key cannot be found in DNS (default: accept)
    //
    // Possible values: accept, discard, quarantine, reject, tempfail
    'opendkim_on_key_not_found'     => 'accept',

    // OpenDKIM operating mode (default: sv)
    //
    // Possible values: s (signer), v (verifier), sv (signer and verifier)
    //
    // Note: If you use SpamAssassin with its DKIM plugin, it is recommended to
    // set the operating mode to 's' (signer). SpamAssassin DKIM plugin will
    // act as verifier.
    'opendkim_operating_mode'       => 'sv',

    // OpenDKIM socket (default: local:<POSTFIX_QUEUE_DIR>/opendkim/opendkim.sock)
    //
    // The Postfix smtpd(8) and cleanup(8) services are chrooted (see the
    // /etc/postfix/master.cf file), hence the UNIX socket must be created
    // inside the Postfix queue directory (/var/spool/postfix).
    //
    // Possible values:
    //  'local:/var/spool/postfix/opendkim/opendkim.sock' for UDS (recommended)
    //  'inet:8891@localhost' for connection through TCP
    //
    // Related parameter: postfix_milter_socket
    'opendkim_socket'               => "local:{$postfixConfig['POSTFIX_QUEUE_DIR']}/opendkim/opendkim.sock",

    // Trusted hosts (default: 127.0.0.1, ::1, localhost, Registry::get('config')['SERVER_HOSTNAME'])
    //
    // Mails coming from these hosts are signed (not verified).
    // Hostnames, IP addresses and CIDR blocks are allowed.
    'opendkim_trusted_hosts'        => [
        '127.0.0.1',
        '::1',
        'localhost',
        Registry::get('config')['SERVER_HOSTNAME']
    ],

    // Additional authserv-ids whose Authentication-Results header fields are
    // removed from incoming mails (default: none)
    //
    // OpenDKIM removes (RemoveARAll/RemoveARFrom) all Authentication-Results
    // header fields that claim to come from this server, so that results
    // forged by a remote sender are never trusted by OpenDMARC, SpamAssassin
    // or MUAs. The i-MSCP server hostname and the Postfix myhostname value are
    // always included. Add here any other authserv-id that only this server
    // may use (e.g. a custom OpenDMARC authserv-id). Don't add hosts that
    // legitimately add such header fields before this server (e.g. a front
    // relay listed in the OpenDMARC opendmarc_trusted_authserv_ids parameter).
    'opendkim_remove_ar_from'       => [],

    // Reject mails that don't comply with the RFC 5322 header field count
    // requirements (RequiredHeaders) (default: no)
    //
    // When enabled, mails without (or with several) From or Date header
    // fields, or with several To, Cc, Subject, Message-Id... header fields are
    // rejected (550). This also blocks the multiple From header fields DMARC
    // bypass, but rejects mails from some broken mailers and scripts (e.g.
    // without Date header field). Possible values: yes, no
    'opendkim_required_headers'     => 'no',

    // OpenDKIM user (default: opendkim)
    'opendkim_user'                 => 'opendkim',

    // Plugin working level (default: admin)
    //
    // Possible values:
    //  admin   : DKIM feature is automatically activated for all customers.
    //  reseller: DKIM feature is activated by resellers for customer of their
    //            choice. This is the historical behavior (prior version 2.0.0).
    'plugin_working_level'          => 'admin',

    // Postfix per-milter default action for OpenDKIM (default: tempfail)
    //
    // Action to be taken by Postfix when the OpenDKIM milter is unavailable.
    // This is set through the Postfix per-milter settings (Postfix >= 3.0),
    // hence the global milter_default_action parameter is left untouched.
    //
    // Possible values: accept, reject, tempfail, quarantine
    'postfix_milter_default_action' => 'tempfail',

    // Postfix milter socket for OpenDKIM (default: unix:/opendkim/opendkim.sock)
    //
    // Path of the OpenDKIM UNIX socket, relative to the Postfix queue
    // directory (chrooted smtpd(8) and cleanup(8) services).
    //
    // Possible values:
    //  'unix:/opendkim/opendkim.sock' for connection through UDS
    //  'inet:localhost:8891' for connection through TCP
    //
    // Related parameter: opendkim_socket
    'postfix_milter_socket'         => 'unix:/opendkim/opendkim.sock'
];
