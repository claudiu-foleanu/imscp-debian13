# iMSCP LetsEncrypt Plugin - Changelog

## Version 1.6.0

Port to i-MSCP 1.5.x on Debian 13 (Trixie).

* Use the Debian certbot package (certbot-auto is discontinued) with the webroot
  authenticator instead of the apache authenticator, which modified the i-MSCP
  Apache configuration
* Single shared ACME challenge directory, exposed for all vhosts (including
  forward, proxy and HTTP to HTTPS redirect vhosts) through a global Apache
  configuration file (conf-available/imscp_sgw_letsencrypt.conf) which is
  enabled with the plugin and removed when it is disabled/uninstalled
* Certificates are imported into the i-MSCP ssl_certs table (key, certificate
  and chain), so that i-MSCP builds the SSL vhosts natively for the
  apache_php_fpm, apache_fcgid and apache_itk httpd servers. The self-signed
  placeholder certificate and the vhost rewriting (afterHttpdBuildConf event
  listener) are gone
* Renewal through the certbot.timer systemd unit; a deploy hook
  (/etc/letsencrypt/renewal-hooks/deploy/imscp-sgw-letsencrypt) re-imports
  renewed certificates into i-MSCP and reloads Apache. The certbot-auto weekly
  cron job is removed
* Disabling Let's Encrypt for a domain removes the certificate from i-MSCP and
  deletes the certbot lineage (optional revocation)
* www.<name> is only included when it resolves; --allow-subset-of-names avoids
  failing whole certificates (and renewals) because of a single name
* ACME account e-mail, --agree-tos, staging server, key type, HSTS and other
  settings through config.php
* Legacy lineages (certbot-auto, apache authenticator) are migrated on update
* Opt-in test mode (certbot mock issuing certificates from a local test CA),
  replacing the certbot-auto-test.pm mock
* Security: certbot/openssl commands are run in list form (no shell),
  customers can only act on their own domains, resellers only see their own
  customers, CSRF token and POST required for state changes, all output
  escaped in templates
* Fixed: viewing the edit page created database rows; reseller page relied on
  non-existent columns (OpenDKIM leftover); plugin name derived as
  'LetsEncrypt' by the plugin API; deletion of a domain alias reset the alias
  status to 'toadd'; items of deleted subdomains/customers were never removed;
  backend errors put the whole plugin in error state; PHP 7.3 / Perl 5.40
  compatibility
* Subdomains of domain aliases are still not supported

## Version 1.4.0

* Fix #13 Support iMSCP 1.4.x

## Version 1.1.1

* Fix #7 Invalid Certificate error

## Version 1.1.0

* Implement #1 Support for aliases and subdomains

## Version 1.0.2

* Fix #2 Plugin blocked delete domain / customer
* Fix #3 Full chain not delivered by Apache

## Version 1.0.0

* Creates domain certificates
* Creates www.domain certificates also with subject alternative name 
* Can forward http -> https

### Known Limitations

* Doesn't support subdomains of aliases
