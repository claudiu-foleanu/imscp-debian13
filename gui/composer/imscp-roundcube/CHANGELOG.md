# Changelog

## 1.1.1

- Security: all operations made in the control panel directory tree (owned
  by the control panel user) are now made with the privileges of that user
  (no more symlink following as root). Configuration files are written
  atomically (O_EXCL|O_NOFOLLOW temporary file + rename); symlinks are refused.
- Security: the upstream archive is verified and extracted from a private
  root-owned temporary directory (the cache is no longer used in place);
  archive members are checked (no absolute path, no '..', no symlink pointing
  outside, no special file, no setuid/setgid bits).
- Security: the Nginx configuration snippet is embedded in the handler and
  installed as root:root 0644 (no longer rendered from the package directory).
- Security: the cron and logrotate files are embedded in the handler; the
  logrotate file now rotates as the control panel user (`su` directive) and
  only `*.log` files.
- Nginx: deny access to plugin helpers, skin/plugin templates, *.py, *.pl and
  *.txt files.

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
