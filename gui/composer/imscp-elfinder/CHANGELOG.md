# Changelog

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
