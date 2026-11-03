# Changelog

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
