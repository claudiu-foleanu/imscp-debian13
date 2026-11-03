# i-MSCP PolicydSPF plugin v1.3.0

Provides Postfix policy server for RFC 7208 SPF checking.

## Introduction

postfix-policyd-spf-python is a full featured Postfix policy engine for Sender
Policy Framework (SPF) checking. It is implemented in Python (python3) and uses
the python3-spf module.

## Requirements

- i-MSCP ≥ 1.5.4 (plugin API ≥ 1.5.1)
- Debian 13 (Trixie) — other distributions are not tested

The `postfix-policyd-spf-python` distribution package is installed
automatically (non-interactive `apt-get install`) on plugin installation and
update.

## Postfix integration

The plugin adds the following service in the Postfix master.cf file:

```
# Plugin::PolicydSPF - Begin
policyd-spf  unix  -       n       n       -       0       spawn
  user=policyd-spf argv=/usr/bin/policyd-spf
# Plugin::PolicydSPF - Ending
```

and the `check_policy_service unix:private/policyd-spf` restriction in the
`smtpd_recipient_restrictions` parameter, right before the final `permit`
(that is, after `reject_unauth_destination` and `permit_sasl_authenticated`,
so authenticated users are not checked), and sets `policyd-spf_time_limit`.

The SPF policy itself is configured through the
`/etc/postfix-policyd-spf-python/policyd-spf.conf` file (Debian defaults:
reject on HELO and MAIL FROM `Fail`, Received-SPF header otherwise). See
policyd-spf.conf(5).

## Installation

1. Be sure that all requirements as stated in the requirements section are met
2. Upload the plugin through the plugin management interface
3. Activate the plugin through the plugin management interface

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

## License

    i-MSCP PolicydSPF plugin
    copyright 2016-2017 Laurent Declercq <l.declercq@nuxwin.com>
    copyright 2016 Ninos Ego <me@ninosego.de>
    
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
