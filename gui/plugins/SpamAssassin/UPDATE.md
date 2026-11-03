# Update to version 2.1.0

## Debian 13 (Trixie) port

This version targets SpamAssassin 4.0.x as provided by Debian 13. Read the
CHANGELOG file for the full list of changes. Main points to take care of:

- The plugin configuration file has new parameters (`spamd.user`,
  `spamd.group`, `spamass_milter.postfix_milter_default_action`,
  `spamassassin.DecodeShortURLs.config_file`) and the `roundcube.markasjunk2`
  parameter has been renamed to `roundcube.markasjunk`. Compare your
  configuration file with the new one before restoring it.
- The SPAMD(8p) socket path is now `/run/spamassassin.sock`. If you restore an
  old configuration file, update both the `spamd.options` and
  `spamass_milter.options` parameters consistently.
- The Bayes tables are emptied by the SQL migration: with the previous schema,
  binary Bayes tokens were stored in an utf8 case-insensitive column, which
  corrupted them (or made learning fail with strict SQL mode). Bayesian
  classifier data must be learned again.
- The AWL table columns are renamed (`count` -> `msgcount`, `last_update` ->
  `last_hit`) as expected by SpamAssassin >= 3.4.2.
- The markasjunk2 Roundcube plugin is replaced by the markasjunk Roundcube core
  plugin. Messages reported as spam/ham are stored in the `sa-learn/spam` and
  `sa-learn/ham` directories and deleted once learned.

# Update to version 2.0.0

## New default configuration values

This new version comes with new default configuration values which better fit
with common usage of SpamAssassin in shared hosting environments and cover the
case where other i-MSCP plugin providing identical features could be
concurrently installed.

### Default policy for SPAM rejection

In previous versions, the default policy for SPAM messages was to reject them.
Doing this in shared hosting environments is really a bad practice as there can
always have false-positive results. A message could be seen as a SPAM when it
is not.

The common rule that dictate how SPAM must be handled by ISPs is that the
decision must be left to end-users. Therefore, the new default policy is to
reject SPAM which score is higher than `15`. That is a good compromise and
greatly mitigates case of false-positive results.

### DKIM, SPF SpamAssassin plugins and RBL checks
 
Both DKIM and SPF SpamAssassin plugins and the SpamAssassin RBL checks are now
disabled by default, covering case where administrator already make usage of
other i-MSCP plugins:

- i-MSCP PolicydSPF plugin: Same as the SPF SpamAssassin plugin
- i-MSCP OpenDKIM plugin: Same as the DKIM SpamAssassin plugin
- i-MSCP Postscreen  plugin: Same as the RBL checks provided by SpamAssassin
- i-MSCP PolicydWeight plugin: Same as the RBL checks provided by SpamAssassin

Excepted the i-MSCP Postscreen plugin usage case, best would be to de-install
the i-MSCP plugins listed above and enable their SpamAssassin counterparts.

## Scores for blacklist and whitelist

Scores for both blacklist and whitelist where resetted to SpamAssassin default
values which fit better for the purpose of that feature.

## SpamAssassin user preferences -- Implementation details

In previous versions, the user preferences were been reset each time the plugin
was being reconfigured, which was a bad implementation. User preferences should
not be resetted when that is not explicitly requested by the administrator.

To solve this problem, the plugin configuration file has been fully rewritten,
now providing the administrator with an additional `enforce ` configuration
parameter that allows to force usage of a specific plugin.

In enforced mode, end-users won't be able to act on the plugin through their
user preferences and existing user preferences for that plugin are deleted.

Note that the `enforce` configuration parameter is only provided for some
plugins.

To resume, the new policy is as follows:

- When a plugin is being enabled, never reset user preferences, excepted if in
  `enforced` mode.
- When a plugin is being disabled, never reset user preferences. This don't
  pose any problem because the SpamAssassin plugin will be fully disabled.

## SPAMD connection mode

In previous versions, connection to SPAMD(8p) was established through TCP.
Starting with this new version, connection is now established through UDS
(Unix Domain Socket).

This is a boost-performance change as the network stack is no longer involved.
