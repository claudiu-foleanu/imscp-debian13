# Changelog

## 1.1.0

- Bundled with i-MSCP as a composer path repository (the original
  github.com/i-MSCP/roundcube repository is gone). Integration code recovered
  from the Software Heritage archive (origin https://github.com/i-MSCP/roundcube,
  branch 1.3.x, revision 0b62353e58f11a6183b418f353863c666a9667ab).
- Roundcube is no longer shipped with the package: the package handler
  downloads the pinned Roundcube release (1.6.20 "complete" tarball) at setup
  time, verifies its SHA-256 checksum and extracts it into the `roundcubemail`
  directory. Composer and install-jsdeps.sh are no longer run.
- Configuration ported to Roundcube 1.6 (`imap_host`, `smtp_host`, ...).
- Enable the archive and zipdownload plugins, and the managesieve and password
  (SQL driver, SHA512-CRYPT) plugins with Dovecot.
- New databases are created with the utf8mb4 character set.
