# i-MSCP OpenDMARC plugin changelog

## Version 1.0.0 (2026-11-03)

- First release (i-MSCP 1.5.4, plugin API 1.5.1, Debian 13 / opendmarc 1.4.2)
- Outbound: `_dmarc` TXT records for customer domains and domain aliases
  (core `domain_dns` table, owner `OpenDMARC_Plugin`), server-wide defaults in
  config.php, per-domain customer overrides, customer-defined `_dmarc`
  records take precedence
- Inbound: OpenDMARC milter after the OpenDKIM milter, `default_action=accept`,
  socket inside the Postfix chroot (0660), managed `/etc/opendmarc.conf` block,
  optional `RejectFailures`
- GUI: customer page (Domains -> DMARC) with edit form, reseller read-only
  overview (Customers -> DMARC)
