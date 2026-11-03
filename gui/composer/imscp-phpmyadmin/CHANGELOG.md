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
- Security: the configuration storage schema is taken from the verified
  release archive and executed through DBI (expected statements only) instead
  of being piped to the mariadb client.
- Security: the control user is no longer granted any privilege on the
  `mysql` system database (only the configuration storage database).
- phpMyAdmin uses its own session directory (data/sessions/phpmyadmin).
- Nginx: deny access to the doc/ directory.

## 1.1.0

- Bundled with i-MSCP as a composer path repository (the original
  github.com/i-MSCP/phpmyadmin repository is gone). Integration code recovered
  from the Software Heritage archive (origin https://github.com/i-MSCP/phpmyadmin,
  tag 1.0.5, revision 8fdc63ec3c6146eeba0b31617c44a672a13223c7).
- phpMyAdmin is no longer pulled through composer (phpmyadmin/phpmyadmin): the
  package handler downloads the pinned phpMyAdmin release (5.2.3
  all-languages tarball) from files.phpmyadmin.net at setup time, verifies its
  SHA-256 checksum and extracts it into the `phpmyadmin` directory.
- Configuration ported to phpMyAdmin 5.2 (32 bytes `blowfish_secret`,
  dedicated `TempDir`, vendor_config.php no longer patched).
- The configuration storage database is no longer dropped on each run.
