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
- Security: login brute-force protection no longer delays requests (which
  could tie up all control panel PHP-FPM workers). Failures are counted per
  client IP address and per username; once a limit is reached, login attempts
  are rejected immediately with HTTP 429 and a Retry-After header. The FTP
  connection made to check credentials uses a 5 seconds timeout.

## 1.1.0

- First release. Replaces the MonstaFTP Web-based FTP client (MonstaFTP
  <= 2.11 is affected by CVE-2025-34299 and the imscp/monsta-ftp repository
  is gone).
- Provides elFinder (https://github.com/Studio-42/elFinder, BSD-3-Clause)
  behind a small i-MSCP login page. Customers log in with their FTP account
  credentials; all file operations go through the local FTP server
  (elFinderVolumeFTP), hence ownership, chroot and quotas enforced by the FTP
  server apply. There is no local filesystem volume.
- elFinder is not shipped with this package: the package handler downloads
  the pinned elFinder release (2.1.70), jQuery (4.0.0) and jQuery UI (1.14.2)
  at setup time and verifies them against pinned SHA-256 checksums.
- Archive creation/extraction, image resizing, folder (zip) download, network
  volume mounting, external editors and every feature relying on shell
  commands are disabled.
