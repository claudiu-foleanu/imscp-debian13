# i-MSCP LetsEncrypt Plugin

Plugin that provides domains with LetsEncrypt SSL certificates.

See [Changelog](CHANGELOG.md) for a detailed description of what has changed in each version.

>Disclaimer: This plugin is not likely to be that well supported.  It works for me, for what I need, right now. YMMV.  If you want a full featured supported plugin I would suggest the [LetsEncrypt Plugin](https://i-mscp.net/filebase/index.php/File/33-LetsEncrypt/) from the iMSCP developers.

Testing and bug reports are welcome.

## Requirements

* i-MSCP 1.5.x (plugin version v1.6.x for Debian 13; v1.5.x for older systems)
* Debian `certbot` package (`/usr/bin/certbot`, provides the `certbot.timer` renewal timer)
* Apache httpd server (apache_php_fpm, apache_fcgid or apache_itk)
* Domains must resolve publicly to this server (HTTP-01 validation on port 80)

## Installation

1. Install the certbot package: `apt-get install certbot`
2. Install and activate the plugin through the plugin management interface
3. Optionally adjust the configuration (`config.php`, or through the plugin
   configuration interface), e.g. the ACME account e-mail address or the
   staging server for testing

## How it works

* Customers enable Let's Encrypt per domain, domain alias or subdomain through
  the *Domains / LetsEncrypt* page (only when the SSL feature is available).
  Resellers get a read-only overview of their customers' certificates.
* The backend requests the certificate with
  `certbot certonly --webroot --cert-name <domain> -d <domain> [-d www.<domain>]`.
  `www.<domain>` is only included when it resolves.
* ACME challenges are served from a single directory
  (`/var/www/imscp/acme-challenge/.well-known/acme-challenge/`), exposed for
  all vhosts through `/etc/apache2/conf-available/imscp_sgw_letsencrypt.conf`
  (enabled with the plugin).
  Note: a `RewriteRule` added by an administrator in a custom vhost
  configuration file could still intercept `/.well-known/acme-challenge/`.
* Certificates stay managed by certbot (`/etc/letsencrypt`) and are imported
  into i-MSCP (SSL certificate of the domain), so i-MSCP builds the SSL vhost.
  "Redirect HTTP to HTTPS" enables the i-MSCP HSTS/redirect feature.
* Renewal is done by the `certbot.timer` systemd unit. The deploy hook
  `/etc/letsencrypt/renewal-hooks/deploy/imscp-sgw-letsencrypt` imports renewed
  certificates into i-MSCP and reloads Apache.
* Disabling Let's Encrypt for a domain removes the certificate from i-MSCP and
  deletes the certbot lineage.
* Disabling the plugin stops renewals (the challenge directory is no longer
  exposed). Uninstalling the plugin deletes the lineages it created; the
  certificates already installed in i-MSCP are left in place until they expire.

## How to Help

* Report issues you find in our [GitHub Issue Tracker](https://github.com/saygoweb/imscp-letsencrypt/issues). Please report with as much detail as you can. Simply saying "It doesn't work" will gain you sympathy, but not a lot else.
* Want to contribute code? Go right ahead, fork the project on GitHub, pull requests are welcome.

## License

```
i-MSCP  SGW_LetsEncrypt plugin
Copyright (C) 2017 Cambell Prince <cambell.prince@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

See [LICENSE](LICENSE)

## Authors

* Cambell Prince <cambell.prince@gmail.com>
