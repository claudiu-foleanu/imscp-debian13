<?php
/**
 * i-MSCP LetsEncrypt plugin
 * Copyright (C) 2017 Cambell Prince <cambell.prince@gmail.com>
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
    // E-mail address used to register the ACME (Let's Encrypt) account. Let's
    // Encrypt sends expiry notices to this address. When empty, the i-MSCP
    // DEFAULT_ADMIN_ADDRESS parameter (/etc/imscp/imscp.conf) is used, then
    // the e-mail of the first administrator. Note that a single ACME account
    // is used for the whole server: the address is only used when the account
    // is registered (first certificate request).
    'email'                   => '',

    // Use the Let's Encrypt staging server (test certificates, not trusted by
    // browsers, much higher rate limits). Recommended for testing.
    'staging'                 => false,

    // Private key type: 'rsa' (2048 bits) or 'ecdsa' (P-256)
    'key_type'                => 'rsa',

    // Whether to add the www.<name> name to the certificates:
    //  'auto'   : only when www.<name> resolves (default)
    //  'always' : always (fails if www.<name> cannot be validated, unless
    //             allow_subset_of_names is enabled)
    //  'never'  : never
    'www'                     => 'auto',

    // Check that names resolve before requesting a certificate
    'check_dns'               => true,

    // Don't fail when some names (e.g. www.<name>) cannot be validated: the
    // certificate is issued (and later renewed) for the names that could be
    // validated.
    'allow_subset_of_names'   => true,

    // HSTS parameters used when "Redirect HTTP to HTTPS" is enabled
    'hsts_max_age'            => 31536000,
    'hsts_include_subdomains' => false,

    // Revoke certificates when Let's Encrypt is disabled for a domain
    // (certificates are always deleted)
    'revoke_on_delete'        => false,

    // Shared ACME challenge directory (webroot). Challenge files are stored in
    // <webroot>/.well-known/acme-challenge/, which is exposed for all vhosts
    // through a global Apache configuration file.
    'webroot'                 => '/var/www/imscp/acme-challenge',

    // Path to the certbot program (Debian certbot package)
    'certbot'                 => '/usr/bin/certbot',

    // TEST MODE: Use a certbot mock which issues certificates from a local
    // test CA instead of contacting Let's Encrypt (state is stored in
    // /var/lib/imscp-sgw-letsencrypt-mock). For testing the i-MSCP
    // integration with domains that don't resolve publicly. NEVER enable it
    // in production.
    'test_mode'               => false
);
