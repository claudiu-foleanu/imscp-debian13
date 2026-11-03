# i-MSCP PolicydWeight plugin v1.4.0

Provides policyd-weight policy daemon for Postfix.

## Introduction

policyd-weight is a Perl policy daemon for the Postfix MTA intended to
eliminate forged envelope senders and HELOs (i.e. in bogus mails). It allows
you to score DNSBLs (RBL/RHSBL), HELO, MAIL FROM and client IP addresses
before any queuing is done. It allows you to REJECT messages which have a score
higher than allowed, providing improved blocking of spam and virus mails.

policyd-weight caches the most frequent client/sender combinations (SPAM as
well as HAM) to reduce the number of DNS queries.

Homepage: https://web.archive.org/web/2018/http://www.policyd-weight.org/ (upstream is dead)

## Requirements

- i-MSCP ≥ 1.5.4 (plugin API ≥ 1.5.1)
- Debian 13 (Trixie) — other distributions are not tested
- A local recursive DNS resolver (e.g. the i-MSCP Bind9 server; nameserver
  127.0.0.1 in /etc/resolv.conf). Spamhaus and SURBL refuse queries coming
  through public resolvers and answer with codes which policyd-weight
  interprets as listings (false positives).

The `policyd-weight` distribution package is installed automatically
(non-interactive `apt-get install`) on plugin installation and update.

Note that Debian 13 (Trixie) is the last Debian release providing the
policyd-weight package (upstream is dead). Consider migrating to the Postfix
postscreen(8) service.

## Installation

1. Be sure that all requirements as stated in the requirements section are met
2. Upload the plugin through the plugin management interface
3. Edit the plugin configuration file according your needs
4. Activate the plugin through the plugin management interface

## Update

1. Be sure that all requirements as stated in the requirements section are met
2. Backup your plugin configuration file if needed
3. Upload the plugin through the plugin management interface

### Restore you plugin configuration file if needed

1. Restore your plugin configuration file (compare it with the new version first)
2. Update the plugin list through the plugin management interface

## Configuration

See [Configuration file](config.php)

When changing a configuration parameter in the plugin configuration file, don't
forget to trigger a plugin list update, else you're changes will not be token
into account.

### policyd-weight configuration options

The plugin manages a `## Begin Plugin::PolicydWeight` ... `## Ending
Plugin::PolicydWeight` block at the end of the /etc/policyd-weight.conf file,
which sets the listening address and port and the DNSBL/RHSBL lists. Other
policyd-weight options (REJECTLEVEL, scores, cache...) can be set in the
/etc/policyd-weight.conf file, outside of that block. See
`/usr/sbin/policyd-weight defaults` for the available options.

The `check_policy_service inet:127.0.0.1:12525` restriction is added in the
`smtpd_recipient_restrictions` parameter, right before the final `permit`
(after `permit_sasl_authenticated` and `reject_unauth_destination`).

## License

    i-MSCP PolicydWeight plugin
    Copyright (C) 2015-2017 Laurent Declercq <l.declercq@nuxwin.com>
    
    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.
    
    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.
    
    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

See [LICENSE](LICENSE)
