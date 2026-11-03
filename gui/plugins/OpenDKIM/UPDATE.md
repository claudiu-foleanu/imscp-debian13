# Version 2.2.0

## Debian 13 (Trixie)

OpenDKIM is now configured exclusively through the `/etc/opendkim.conf` file,
as expected by the Debian 13 opendkim package. The `/etc/default/opendkim`
block and the systemd `override.conf`/`tmpfiles.d` files that were created by
previous versions are removed on activation.

The OpenDKIM socket has been moved from
`/var/spool/postfix/var/run/opendkim/opendkim.sock` to
`/var/spool/postfix/opendkim/opendkim.sock` (Postfix milter:
`unix:/opendkim/opendkim.sock`). The old Postfix milter values are removed on
update.

## ADSP removal

ADSP (Author Domain Signing Practices) has been declared historic (RFC 8553)
and is no longer supported by opendkim. The `opendkim_adsp*` parameters have
been removed and the ADSP DNS resource records are removed on activation.

## New parameters

- `opendkim_on_bad_signature` and `opendkim_on_key_not_found` (default: `accept`)
- `postfix_milter_default_action` (default: `tempfail`)

## Removed parameters

- `opendkim_adsp`, `opendkim_adsp_action`, `opendkim_adsp_no_such_domain`,
  `opendkim_adsp_signing_practice`
- `opendkim_rundir`, `postfix_rundir`

Compare your configuration file with the new one before updating.

# Version 2.0.0

## DKIM keys display

DKIM Keys are not longer displayed through textarea html tags. They are now
displayed through tooltips which are shown when the mouse pass over a button
that allows the customer to easily copy the DKIM keys into the clipboard.

## DKIM keys renewal

Resellers can now trigger renewal of their customers's DKIM keys through their
OpenDKIM interface.

## DKIM support for subdomains

Messages sent from a subdomain are signed using the DKIM key of its parent
domain. This is perfectly valid and supported.

## Plugin working level

Starting with this version, it is possible to choose the plugin working level
through the `plugin_working_level` plugin configuration parameter. There are
actually two working levels which are `admin` and `reseller`.

When it works at the `admin` level, the plugin activates OpenDKIM for all
customers automatically. In this working level, resellers can only trigger DKIM
keys renewal through their own management interface. This is the new default
behavior.

When it works at `reseller` level, the plugin doesn't activate OpenDKIM
automatically for customers. Resellers must enable the OpenDKIM feature
manually for all of their customers. This is the historical (pre-version 2.0.0)
behavior.
