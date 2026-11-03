# i-MSCP OpenDMARC plugin

DMARC ([RFC 7489](https://tools.ietf.org/html/rfc7489)) support for i-MSCP 1.5.x
(plugin API 1.5.1), Debian 13 (Trixie).

## Features

### Outbound: DMARC policy records

- A `_dmarc.<domain> IN TXT "v=DMARC1; p=...; ..."` record is published for
  every customer domain and domain alias, through the core `domain_dns` table
  (`owned_by = 'OpenDMARC_Plugin'`). Records are published by the core
  `Modules::CustomDNS` module and the named server (Bind9), exactly like the
  OpenDKIM plugin DKIM records.
- Subdomains get no record of their own: receivers apply the organizational
  domain record to them (`p=`, or `sp=` when set).
- Records follow the domain/domain alias lifecycle (added/removed with the
  domain, disabled with suspended customers) and the plugin lifecycle
  (disabled on deactivation, re-enabled on activation, deleted on
  uninstallation).
- Server-wide defaults are set in `config.php` (plugin manager). The default
  policy is `p=none` (monitoring only, safe start).
- Customers can override the defaults per domain (Domains -> DMARC): policy
  (`p`), subdomain policy (`sp`), percentage (`pct`), DKIM/SPF alignment
  (`adkim`/`aspf`), aggregate/failure report addresses (`rua`/`ruf`). A
  warning is displayed when a quarantine/reject policy is chosen for a domain
  without DKIM key (OpenDKIM plugin).
- A customer-defined `_dmarc` record (custom DNS records feature) always wins:
  the plugin record is withdrawn (and logged) as long as it exists, and
  re-published when it is removed. Two DMARC records for the same name would
  make the policy invalid for receivers.
- Resellers get a read-only overview of their customers' DMARC records
  (Customers -> DMARC).

### Inbound: DMARC verification (OpenDMARC milter)

- Debian package `opendmarc` (1.4.2), installed non-interactively (the
  dbconfig-common database used for aggregate reports is declined through
  debconf preseeding: reporting/history is not used).
- `/etc/opendmarc.conf` is managed through a block delimited by
  `# Begin Plugin::OpenDMARC` / `# Ending Plugin::OpenDMARC`. Distribution
  settings that are overridden are commented out with the `#Plugin::OpenDMARC# `
  prefix and restored on deactivation. The configuration is checked with
  `opendmarc -n` before the service is restarted.
- Socket: `local:/var/spool/postfix/opendmarc/opendmarc.sock` (inside the
  Postfix chroot). The directory is `opendmarc:opendmarc 0750` (the systemd
  unit runs opendmarc as the opendmarc user, which creates the socket), the
  socket is `0660` (`UMask 0117`) and the postfix user is added to the
  opendmarc group. Nothing is world-accessible.
- The milter is added to `smtpd_milters` only, right **after** the OpenDKIM
  milter (OpenDMARC consumes the DKIM results from the Authentication-Results
  header field added by OpenDKIM), with a per-milter
  `default_action=accept`: mail is never blocked because the DMARC milter is
  down. Other milters (SpamAssassin, OpenDKIM, ClamAV...) are left untouched.
  If the OpenDKIM plugin is (re)activated later and appends its milter after
  ours, the order is fixed on the next backend run.
- `AuthservID` is the server hostname; `TrustedAuthservIDs` contains it plus
  the Postfix `myhostname` (authserv-id used by OpenDKIM by default).
- `IgnoreAuthenticatedClients true` and `IgnoreHosts` (127.0.0.1, ::1, the
  Postfix `mynetworks` entries and `opendmarc_ignore_hosts`): outgoing mail
  isn't evaluated.
- SPF: `SPFIgnoreResults true` + `SPFSelfValidate true`. OpenDMARC always
  performs its own SPF check and never trusts SPF results found in the message
  header (Received-SPF or Authentication-Results). This doesn't depend on the
  PolicydSPF plugin being active and can't be fooled by a forged SPF header
  field (CVE-2019-20790 class of issues). The cost is one extra SPF
  evaluation per message when policyd-spf also runs.
- `RejectFailures` (`opendmarc_reject_failures`, default `false`): only an
  `Authentication-Results: <host>; dmarc=pass|fail|none ...` header field is
  added. With `true`, mail failing DMARC from domains publishing `p=reject`
  is rejected, and mail that couldn't be evaluated (DNS errors) is
  temp-failed.
- `HistoryFile`, `FailureReports`: off (no reporting, no database).
- `SoftwareHeader false`, `RequiredHeaders false`.

## Installation

1. Upload the plugin archive through the plugin manager (or copy the
   `OpenDMARC` directory into `gui/plugins`), update the plugin list.
2. Review `config.php` (defaults, report addresses, RejectFailures).
3. Activate the plugin.

## Configuration (config.php)

| Parameter | Default | Description |
| --- | --- | --- |
| `dmarc_policy` | `none` | Default `p=` (none, quarantine, reject) |
| `dmarc_subdomain_policy` | `''` | Default `sp=` (empty: tag omitted) |
| `dmarc_pct` | `100` | Default `pct=` (100: tag omitted) |
| `dmarc_adkim` / `dmarc_aspf` | `r` | Default alignment modes |
| `dmarc_rua` / `dmarc_ruf` | `''` | Default report addresses (empty: no report) |
| `dmarc_dns_records_ttl` | `3600` | TTL of the records (60..86400) |
| `customer_can_edit` | `true` | Customers can override the defaults |
| `opendmarc_reject_failures` | `false` | OpenDMARC `RejectFailures` |
| `opendmarc_authserv_id` | server hostname | `AuthservID` |
| `opendmarc_trusted_authserv_ids` | `[]` | Additional `TrustedAuthservIDs` |
| `opendmarc_ignore_hosts` | `[]` | Additional `IgnoreHosts` entries |
| `opendmarc_socket` | `local:/var/spool/postfix/opendmarc/opendmarc.sock` | OpenDMARC socket |
| `postfix_milter_socket` | `unix:/opendmarc/opendmarc.sock` | Socket as seen by chrooted Postfix |
| `postfix_milter_default_action` | `accept` | Per-milter default action |

Report addresses: when the report address domain differs from the policy
domain, the report domain must authorize it (RFC 7489 section 7.1), e.g.
`example.com._report._dmarc.reports.example.net IN TXT "v=DMARC1"`.

## Security notes

- Commands are always executed in list form (no shell).
- Every value written into DNS records or configuration files is validated
  (strict whitelists, `\z` anchors: no newline/quote/semicolon injection).
  The GUI validates the same way and the backend re-validates stored values.
- `/etc/opendmarc.conf` (root:root 0644) and `/etc/opendmarc/ignore.hosts`
  (root:root 0644, directory root:root 0755) are written atomically
  (temporary file + rename) in root-owned directories whose path is checked;
  symlinks are refused, ownership/permissions are set through file
  descriptors opened with O_NOFOLLOW.
- GUI: `check_login()`, every query is scoped to the logged-in customer
  (`domain_admin_id`) or reseller (`created_by`), POST + per-session CSRF
  token (`hash_equals`), all output escaped.
- Residual risk: OpenDMARC trusts Authentication-Results header fields bearing
  a trusted authserv-id. A sender can forge such a header field with a
  `dkim=pass` result. Removing incoming A-R header fields bearing our
  authserv-id (e.g. OpenDKIM `RemoveARFrom`/`RemoveARAll`) closes this gap.

## Uninstallation

Deactivation stops/disables the opendmarc service, removes the milter, the
socket directory and the postfix group membership, restores
`/etc/opendmarc.conf` and disables the DNS records. Uninstallation deletes
the DNS records and the `opendmarc` table, removes `/etc/opendmarc` and purges
the opendmarc package.

## License

GPL-2.0-or-later. See the LICENSE file.
