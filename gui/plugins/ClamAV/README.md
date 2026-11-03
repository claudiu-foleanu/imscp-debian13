# i-MSCP ClamAV plugin v1.4.0

Provides ClamAV anti-virus through MILTER.

## Requirements

- i-MSCP Serie ≥ 1.5.x (tested with i-MSCP 1.5.4 on Debian 13 Trixie)
- Postfix as MTA

The plugin installs the following Debian packages itself (non-interactive
APT(8) run on plugin installation/update):

- clamav, clamav-base, clamav-daemon, clamav-freshclam, clamav-milter, clamdscan
- curl, gnupg, rsync, bind9-dnsutils (needed by clamav-unofficial-sigs)

## Postfix integration

The plugin adds its own milter entry to the Postfix `smtpd_milters` and
`non_smtpd_milters` parameters, using the Postfix per-milter settings syntax:

```
smtpd_milters = { unix:/clamav/clamav-milter.ctl, default_action=tempfail }
```

Milter entries added by other plugins (OpenDKIM, SpamAssassin...) are left
untouched, and so is the global `milter_default_action` parameter.

Because the Postfix smtpd(8) and cleanup(8) services run chrooted on Debian,
the clamav-milter socket is created under the Postfix queue directory
(`/var/spool/postfix/clamav/clamav-milter.ctl`) and referenced by Postfix
relative to its chroot (`unix:/clamav/clamav-milter.ctl`).

## Installation

1. Be sure that all requirements as stated in the requirements section are met
2. Upload the plugin through the plugin management interface
3. Activate the plugin through the plugin management interface

Note that installation can take-up several minutes because the ClamAV virus
databases must be initialized, involving download of several cvd files.

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

## 3rd party ClamAV Unofficial Signatures

The [clamav-unofficial-sigs](https://github.com/extremeshok/clamav-unofficial-sigs)
script (bundled version: 8.0.0) provides a simple way to download, test, and
update third-party signature databases provided by:

- [Sanesecurity](http://sanesecurity.com) (including Foxhole, OITC, Scamnailer,
  BOFHLAND, CRDF, Porcupine...)
- [SecuriteInfo](https://www.securiteinfo.com) (requires a free account)
- [MalwarePatrol](https://www.malwarepatrol.net) (requires a free account)
- [InterServer](https://sigs.interserver.net)
- [URLhaus](https://urlhaus.abuse.ch)
- [Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/)
- [Yara-Rules Project](https://github.com/Yara-Rules/rules) (disabled by
  default: deprecated upstream, several rules crash ClamAV ≥ 1.0)

The script is installed as `/usr/local/sbin/clamav-unofficial-sigs.sh`. Its
configuration is generated in `/etc/clamav-unofficial-sigs` and an hourly cron
task is installed in `/etc/cron.d/clamav-unofficial-sigs` (run as the `clamav`
user). Self-upgrade and upgrade checks are disabled.

If you already have this or another script that downloads 3rd party ClamAV
signatures, then please uninstall or remove it before using this plugin with
[clamav-unofficial-sigs](https://github.com/extremeshok/clamav-unofficial-sigs)
activated.

## Eicar-Test-Signature

Send a mail with the following content to one of your i-MSCP mail accounts:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Be aware that the EICAR signature above must be added on a line, without
whitespace nor line break.

You can also test from the command line (swaks package):

```
swaks --server localhost:25 --to user@domain.tld --body 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
```

### Expected result in /var/log/mail.log

```
root@precise:/etc/postfix# tail -fn0 /var/log/mail.log
Feb 20 03:26:16 precise postfix/smtpd[19062]: connect from unknown[192.168.5.100]
Feb 20 03:26:16 precise postfix/smtpd[19062]: Anonymous TLS connection established from unknown[192.168.5.100]: TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits)
Feb 20 03:26:16 precise postfix/smtpd[19062]: 0A618260345: client=unknown[192.168.5.100], sasl_method=CRAM-MD5, sasl_username=nuxwin@domain.tld
Feb 20 03:26:16 precise postfix/cleanup[19158]: 0A618260345: message-id=<54E6A8BF.3080504@domain.tld>
Feb 20 03:26:16 precise clamav-milter[18878]: Message from <nuxwin@domain.tld> to <nuxwin@domain.tld> infected by Eicar-Test-Signature
Feb 20 03:26:16 precise postfix/cleanup[19158]: 0A618260345: milter-reject: END-OF-MESSAGE from unknown[192.168.5.100]: 5.7.1 Blocked by ClamAV - FOUND VIRUS: Eicar-Test-Signature; from=<nuxwin@domain.tld> to=<nuxwin@domain.tld> proto=ESMTP helo=<[192.168.5.100]>
```

## License

    i-MSCP ClamAV plugin
    Copyright (C) 2014-2017 Laurent Declercq <l.declercq@nuxwin.com>
    Copyright (C) 2013-2017 Rene Schuster <mail@reneschuster.de>
    Copyright (C) 2013-2016 Sascha Bay <info@space2place.de>
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 of the License
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
