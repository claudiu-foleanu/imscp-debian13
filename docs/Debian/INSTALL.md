# i-MSCP installation on Debian

## Supported Debian versions

- Debian Stretch (9.x)
- Debian Buster (10.x)
- Debian Trixie (13.x)

### Debian Trixie (13.x) notes

- The control panel itself (imscp_panel service) still runs on PHP 7.3, which
  is provided by the [Sury](https://packages.sury.org/php/) repository. Customer
  sites can use any PHP version from 5.6 to 8.4.
- MariaDB 11.8 (distribution package) is installed as SQL server.
- Dovecot 2.4 is supported (new configuration syntax).
- Third-party APT repositories are written in the
  `/etc/apt/sources.list.d/imscp.list` file and their keys are stored in the
  `/etc/apt/keyrings` directory as the `apt-key` command is no longer
  available. Both `/etc/apt/sources.list` and the deb822
  `/etc/apt/sources.list.d/*.sources` formats are supported.
- Customer PHP defaults to PHP 8.4 (all versions from 5.6 to 8.4 can be
  selected through the `PHP_SERVER` parameter).
- Web add-ons: Roundcube 1.6 (webmail), phpMyAdmin 5.2 and elFinder (web
  file manager over FTP, replaces MonstaFTP) are downloaded from upstream at
  setup time and verified against pinned SHA-256 checksums. RainLoop and
  MonstaFTP are no longer available.
- Tested server implementations: Apache2 (PHP-FPM, FastCGI and ITK),
  Dovecot and Courier, ProFTPD and VsFTPD, Bind9, Postfix, local MariaDB.

### DNS requirements

For mail to be accepted by other mail servers, make sure that, in the public
DNS:

- the server hostname (e.g. `server.example.com`) and the control panel
  hostname (e.g. `panel.example.com`) resolve to the server IP address
- the reverse DNS (PTR record) of the server IP address points to the server
  hostname

## Installation

### 1. Make sure that your distribution is up-to-date

```
apt-get update
apt-get --assume-yes --auto-remove --no-install-recommends dist-upgrade
```

### 2. Install the pre-required packages

```
apt-get -y --auto-remove --no-install-recommends install ca-certificates perl \
whiptail wget
```

### 3. Download and un-tar the distribution files

```
cd /usr/local/src
wget https://github.com/i-MSCP/imscp/archive/<release_tag>.tar.gz
tar -xzf imscp-<release_tag>.tar.gz
```

### 4. Change to the newly created directory

```
cd imscp-<release_tag>
```

### 5. Install i-MSCP by running its installer

```
perl imscp-autoinstall -d
```

Note that by default, not all setup dialogs are displayed, that is, those for
which a default value is available. If you want force the installer to display
all setup dialogs, you need to pass the `--reconfigure` option, without any
argument, to the installer.

You can have a look at the [preseeding template file](../preseed.pl) to know
the default values used by the installer.

## i-MSCP Upgrade

### 1. Make sure to read the errata file

Before upgrading, you must not forget to read the
[errata file](https://github.com/i-MSCP/imscp/blob/<release_tag>/docs/<release_branch>_errata.md)

### 2. Make sure to make a backup of your data

Before any upgrade attempt it is highly recommended to make a backup of the
following directories:

```
/var/www/virtual
/var/mail/virtual
```

These directories hold the data of your customers and it is really important to
backup them for an easy recovering in case something goes wrong during upgrade.

### 3. Make sure that your distribution is up-to-date

```
apt-get update
apt-get --assume-yes --auto-remove --no-install-recommends dist-upgrade
```

### 4. Download and un-tar the distribution files

```
cd /usr/local/src
wget https://github.com/i-MSCP/imscp/archive/<release_tag>.tar.gz
tar -xzf imscp-<release_tag>.tar.gz
```

### 5. Change to the newly created directory

```
cd imscp-<release_tag>
```

### 6. Update i-MSCP by running its installer

```
perl imscp-autoinstall -d
```
