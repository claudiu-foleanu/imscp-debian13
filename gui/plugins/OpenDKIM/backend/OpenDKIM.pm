=head1 NAME

 Plugin::OpenDKIM

=cut

# i-MSCP OpenDKIM plugin
# Copyright (C) 2013-2017 Laurent Declercq <l.declercq@nuxwin.com>
# Copyright (C) 2013-2016 Rene Schuster <mail@reneschuster.de>
# Copyright (C) 2013-2016 Sascha Bay <info@space2place.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package Plugin::OpenDKIM;

use strict;
use warnings;
use iMSCP::Database;
use iMSCP::Debug qw/ debug error getMessageByType /;
use iMSCP::Dir;
use iMSCP::Execute qw/ execute /;
use iMSCP::File;
use iMSCP::Service;
use iMSCP::TemplateParser qw/ getBloc replaceBloc /;
use iMSCP::SystemUser;
use Servers::mta;
use Cwd qw/ realpath /;
use Fcntl qw/ O_RDONLY O_NOFOLLOW O_NONBLOCK O_DIRECTORY S_ISDIR S_ISREG S_ISVTX S_IWGRP S_IWOTH /;
use File::Basename qw/ basename dirname /;
use File::Path qw/ remove_tree /;
use File::Temp ();
use Text::Balanced qw/ extract_multiple extract_delimited /;
use version;
use parent 'Common::SingletonClass';

# Marker used to comment out distribution opendkim.conf(5) settings that are
# overridden by this plugin. Those lines are restored on deactivation.
my $CONF_COMMENT_MARKER = '#Plugin::OpenDKIM# ';

# opendkim.conf(5) settings managed by this plugin
my @MANAGED_CONF_KEYS = qw/
    Canonicalization ExternalIgnoreList InternalHosts KeyTable LogWhy
    MinimumKeyBits Mode On-BadSignature On-KeyNotFound OversignHeaders PidFile
    RequireSafeKeys SignatureAlgorithm SigningTable SoftwareHeader Socket
    Syslog SyslogSuccess UMask UserID
/;

# opendkim-genkey location (Debian 13: /usr/sbin; older releases: /usr/bin)
our @GENKEY_PATHS = qw( /usr/sbin/opendkim-genkey /usr/bin/opendkim-genkey );

# Valid (ASCII/punycode) domain name
my $DOMAIN_NAME_RE = qr/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

=head1 DESCRIPTION

 This package provides the backend part for the i-MSCP OpenDKIM plugin.

 Debian 13 (Trixie) notes:
  - opendkim 2.11 is configured exclusively through /etc/opendkim.conf
    (the systemd unit runs /usr/sbin/opendkim without arguments). The
    /etc/default/opendkim file and opendkim.service.generate script are
    deprecated and no longer used by this plugin.
  - The milter socket is created inside the Postfix queue directory (default:
    /var/spool/postfix/opendkim/opendkim.sock) because the Postfix smtpd(8)
    and cleanup(8) services are chrooted.
  - ADSP (RFC 5617) has been declared historic (RFC 8553 / IESG 2013) and
    is not supported by opendkim >= 2.10. ADSP DNS records are removed.

 Security notes (ownership and permissions):
  - This backend runs as root. The OpenDKIM configuration directory, the
    keys/ directory, the per-domain key directories and the KeyTable,
    SigningTable and TrustedHosts files are root-owned (root:opendkim
    0750/0640) so that the opendkim user can read them but never plant
    symlinks or hard links that root would follow.
  - Private keys (keys/<domain>/mail.private) are owned by the opendkim user
    with mode 0600. opendkim(8) only reads them. They cannot be group-readable
    (root:opendkim 0640) because the Postfix user is a member of the opendkim
    group (socket access) and RequireSafeKeys refuses keys that are readable
    by another user through the group.
  - Keys are generated in a private root-owned temporary directory and then
    moved in place. Files are written atomically (temporary file + rename(2))
    and ownership/permissions are only ever changed through file descriptors
    opened with O_NOFOLLOW. Symlinks are refused.

=head1 PUBLIC METHODS

=over 4

=item uninstall( )

 Perform uninstall tasks

 Return int 0 on success, other on failure

=cut

sub uninstall
{
    my ($self) = @_;

    local $@;
    eval {
        debug( 'Deleting all DKIM DNS records' );
        local $self->{'dbh'}->{'RaiseError'} = 1;
        $self->{'dbh'}->do( "DELETE FROM domain_dns WHERE owned_by = 'OpenDKIM_Plugin'" );

        if ( -d $self->{'config_prev'}->{'opendkim_confdir'} ) {
            debug( "Removing $self->{'config_prev'}->{'opendkim_confdir'} directory" );
            iMSCP::Dir->new( dirname => $self->{'config_prev'}->{'opendkim_confdir'} )->remove();
        }

        $self->_uninstallDistributionPackages();
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item update( $fromVersion )

 Perform update tasks

 Param string $fromVersion Version from which the plugin is being updated
 Return int 0 on success, other on failure

=cut

sub update
{
    my ($self, $fromVersion) = @_;

    local $@;
    eval {
        $fromVersion = version->parse( $fromVersion );

        if ( $fromVersion < version->parse( '1.1.0' ) && defined $self->{'config_prev'}->{'opendkim_port'} ) {
            debug( 'Removing Postfix milter value from opendkim_port (prev)' );
            my @milterPrevValues = ( qr/\Qinet:localhost:$self->{'config_prev'}->{'opendkim_port'}\E/ );
            Servers::mta->factory()->postconf(
                smtpd_milters     => { action => 'remove', values => [ @milterPrevValues ] },
                non_smtpd_milters => { action => 'remove', values => [ @milterPrevValues ] }
            ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
        }

        if ( $fromVersion < version->parse( '1.1.1' ) ) {
            debug( 'Removing possible opendkim_feature orphaned DNS record entries' );
            local $self->{'dbh'}->{'RaiseError'} = 1;
            $self->{'dbh'}->do( "DELETE FROM domain_dns WHERE owned_by = 'opendkim_feature'" );
        }

        # ADSP support has been removed in version 2.2.0. Removal of the DKIM
        # ADSP DNS records and subdomain entries is done in the enable()
        # method, as this must also be done on re-activation.
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item change( )

 Perform change tasks

 Return int 0 on success, other on failure

=cut

sub change
{
    my ($self) = @_;

    local $@;
    eval {
        if ( -d $self->{'config'}->{'opendkim_confdir'} ) {
            debug( "Fixing permissions on $self->{'config'}->{'opendkim_confdir'} directory" );
            $self->_secureConfDir();
        }

        if ( $self->{'config'}->{'opendkim_dns_records_ttl'} ne ( $self->{'config_prev'}->{'opendkim_dns_records_ttl'} // '' ) ) {
            debug( 'Updating DKIM DNS records TTL' );
            local $self->{'dbh'}->{'RaiseError'} = 1;
            $self->{'dbh'}->do(
                "
                    UPDATE domain_dns
                    SET domain_dns = CONCAT(SUBSTRING_INDEX(domain_dns, ' ', 1), ' ', ?), domain_dns_status = 'tochange'
                    WHERE owned_by = 'OpenDKIM_Plugin'
                    AND domain_dns_status <> 'todelete'
                ",
                undef, $self->{'config'}->{'opendkim_dns_records_ttl'}
            );
        }
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item enable( )

 Perform enable tasks

 Return int 0 on success, other on failure

=cut

sub enable
{
    my ($self) = @_;

    local $@;
    eval {
        $self->_installDistributionPackages() if grep ( $_ eq $self->{'action'}, 'install', 'update' );

        {
            local $self->{'dbh'}->{'RaiseError'} = 1;
            # ADSP is historic (RFC 8553) and unsupported since opendkim 2.10:
            # remove any ADSP DNS record and subdomain entries (only used for ADSP)
            # left by plugin versions < 2.2.0
            $self->{'dbh'}->do(
                "
                    UPDATE domain_dns SET domain_dns_status = 'todelete'
                    WHERE owned_by = 'OpenDKIM_Plugin'
                    AND domain_dns LIKE '\\_adsp.%'
                "
            );
            $self->{'dbh'}->do( 'DELETE FROM opendkim WHERE is_subdomain = 1' );
        }

        $self->_opendkimSetup( 'configure' );
        $self->_postfixSetup( 'configure' );
        $self->_addMissingOpenDKIMEntries();

        local $self->{'dbh'}->{'RaiseError'} = 1;
        $self->{'dbh'}->do(
            "
                UPDATE domain_dns SET domain_dns_status = 'toenable'
                WHERE domain_dns_status NOT IN('todelete', 'toadd')
                AND owned_by = 'OpenDKIM_Plugin'
            "
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item disable( )

 Perform disable tasks

 Return int 0 on success, other on failure

=cut

sub disable
{
    my ($self) = @_;

    local $@;
    eval {
        if ( $self->{'action'} eq 'disable' ) {
            # Only on real deactivation. On change/update, the plugin is
            # re-enabled straight away.
            local $self->{'dbh'}->{'RaiseError'} = 1;
            $self->{'dbh'}->do(
                "
                    UPDATE domain_dns SET domain_dns_status = 'todisable'
                    WHERE domain_dns_status NOT IN('todelete', 'disabled')
                    AND owned_by = 'OpenDKIM_Plugin'
                "
            );
        }

        $self->_postfixSetup( 'deconfigure' );
        $self->_opendkimSetup( 'deconfigure' );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item run( )

 Process OpenDKIM entries

 Return int 0 on success, other on failure

=cut

sub run
{
    my ($self) = @_;

    local $@;
    eval {
        local $self->{'dbh'}->{'RaiseError'} = 1;
        my $rows = $self->{'dbh'}->selectall_arrayref(
            "
                SELECT opendkim_id, domain_id, IFNULL(alias_id, 0) AS alias_id, domain_name, is_subdomain, opendkim_status
                FROM opendkim
                WHERE opendkim_status IN('toadd', 'tochange', 'todelete')
            ",
            { Slice => {} }
        );

        return unless @{$rows};

        # Make sure that the configuration directory is root-owned (also
        # migrate installations made by older plugin versions, where the
        # directory was owned by the opendkim user) before any write.
        $self->_secureConfDir();

        for my $row ( @{$rows} ) {
            local $@;
            eval {
                if ( $row->{'opendkim_status'} eq 'todelete' ) {
                    $self->_deleteDomain( $row );
                    $self->{'dbh'}->do( 'DELETE FROM opendkim WHERE opendkim_id = ?', undef, $row->{'opendkim_id'} );
                    return;
                }

                $self->_addDomain( $row );
                $self->{'dbh'}->do( "UPDATE opendkim SET opendkim_status = 'ok' WHERE opendkim_id = ?", undef, $row->{'opendkim_id'} );
            };
            if ( $@ ) {
                my $err = $@;
                $err =~ s/\s+at\s+\S+\s+line\s+\d+\.?\s*$//;
                $self->{'dbh'}->do(
                    'UPDATE opendkim SET opendkim_status = ? WHERE opendkim_id = ?',
                    undef, ( getMessageByType( 'error', { amount => 1, remove => 1 } ) || $err || 'Unknown error' ),
                    $row->{'opendkim_id'}
                );
            }
        }

        # Make OpenDKIM reload its KeyTable/SigningTable (SIGUSR1)
        $self->_reloadOpendkim();
    };
    if ( $@ ) {
        $self->{'FORCE_RETVAL'} = 1;
        error( $@ );
        return 1;
    }

    0;
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 Initialize plugin

 Return Plugin::OpenDKIM, die on failure

=cut

sub _init
{
    my ($self) = @_;

    for my $param ( qw/
        opendkim_canonicalization opendkim_confdir opendkim_dns_records_ttl opendkim_group opendkim_keysize
        opendkim_on_bad_signature opendkim_on_key_not_found opendkim_operating_mode opendkim_socket
        opendkim_trusted_hosts opendkim_user plugin_working_level postfix_milter_default_action postfix_milter_socket
        /
    ) {
        defined $self->{'config'}->{$param} or die(
            sprintf( "Missing or undefined `%s' plugin configuration parameter", $param )
        );
    }

    $self->{'config_prev'} ||= {};

    # Fill-in missing previous parameters (e.g. after update from an older
    # version) with current values
    for my $param ( keys %{$self->{'config'}} ) {
        $self->{'config_prev'}->{$param} //= $self->{'config'}->{$param};
    }

    # Sanity checks (values end in configuration files)
    my $c = $self->{'config'};
    $c->{'opendkim_keysize'} =~ /^\d+$/ && $c->{'opendkim_keysize'} >= 1024 or die(
        "Invalid `opendkim_keysize' parameter. Integer >= 1024 expected."
    );
    $c->{'opendkim_dns_records_ttl'} =~ /^\d+$/ or die( "Invalid `opendkim_dns_records_ttl' parameter. Integer expected." );
    $c->{'opendkim_canonicalization'} =~ m%^(?:simple|relaxed)(?:/(?:simple|relaxed))?$% or die(
        "Invalid `opendkim_canonicalization' parameter."
    );
    $c->{'opendkim_operating_mode'} =~ /^(?:s|v|sv|vs)$/ or die( "Invalid `opendkim_operating_mode' parameter." );
    for ( qw/ opendkim_on_bad_signature opendkim_on_key_not_found / ) {
        $c->{$_} =~ /^(?:a|accept|d|discard|q|quarantine|r|reject|t|tempfail)$/ or die( "Invalid `$_' parameter." );
    }
    $c->{'postfix_milter_default_action'} =~ /^(?:accept|reject|tempfail|quarantine)$/ or die(
        "Invalid `postfix_milter_default_action' parameter."
    );
    $c->{'plugin_working_level'} =~ /^(?:admin|reseller)$/ or die( "Invalid `plugin_working_level' parameter." );
    ref $c->{'opendkim_trusted_hosts'} eq 'ARRAY' or die( "Invalid `opendkim_trusted_hosts' parameter. Array expected." );
    for ( qw/ opendkim_confdir opendkim_socket opendkim_user opendkim_group postfix_milter_socket / ) {
        $c->{$_} =~ /^[^\s{},]+$/ or die( "Invalid `$_' parameter." );
    }
    for ( @{$c->{'opendkim_trusted_hosts'}} ) {
        defined && /^[^\s]+$/ or die( "Invalid entry in the `opendkim_trusted_hosts' parameter." );
    }

    $self->{'dbh'} = iMSCP::Database->factory()->getRawDb();
    $self;
}

=item _installDistributionPackages( )

 Install OpenDKIM distribution packages (non-interactive)

 Return void, die on failure

=cut

sub _installDistributionPackages
{
    debug( 'Installing distribution packages' );
    local $ENV{'DEBIAN_FRONTEND'} = 'noninteractive';
    local $ENV{'UCF_FORCE_CONFFOLD'} = 1;
    my $stderr;
    execute( [ 'apt-get', 'update' ], \my $stdout, \$stderr ) == 0 or die(
        sprintf( "Couldn't update APT index: %s", $stderr || 'Unknown error' )
    );
    debug( $stdout ) if $stdout;
    execute(
        [
            'apt-get', '-o', 'DPkg::Options::=--force-confold', '-o', 'DPkg::Options::=--force-confdef',
            '-o', 'DPkg::Options::=--force-confmiss', '--assume-yes', '--no-install-recommends', '--quiet',
            'install', 'opendkim', 'opendkim-tools', 'openssl'
        ],
        \$stdout, \$stderr
    ) == 0 or die( sprintf( "Couldn't install distribution packages: %s", $stderr || 'Unknown error' ));
    debug( $stdout ) if $stdout;
}

=item _uninstallDistributionPackages()

 Uninstall OpenDKIM distribution packages (non-interactive)

 Return void, die on failure

=cut

sub _uninstallDistributionPackages
{
    debug( 'Uninstalling distribution packages' );
    local $ENV{'DEBIAN_FRONTEND'} = 'noninteractive';
    my $stderr;
    execute(
        [ 'apt-get', '--assume-yes', '--purge', '--quiet', 'remove', 'opendkim', 'opendkim-tools' ], \my $stdout, \$stderr
    ) == 0 or die( sprintf( "Couldn't uninstall distribution packages: %s", $stderr || 'Unknown error' ));
    debug( $stdout ) if $stdout;
}

=item _getSocketDir( $socket )

 Get the directory of the given OpenDKIM UNIX socket

 Param string $socket OpenDKIM socket specification (local:/path/to/socket or inet:port@host)
 Return string|undef Socket directory or undef if the socket isn't a UNIX socket

=cut

sub _getSocketDir
{
    my (undef, $socket) = @_;

    return unless defined $socket && $socket =~ m%^(?:local|unix):(/.+)/[^/]+$%;
    $1;
}

=item _opendkimSetup( $action )

 Configure or deconfigure OpenDKIM

 Param string $action Action to be performed (configure|deconfigure)
 Return void, die on failure

=cut

sub _opendkimSetup
{
    my ($self, $action) = @_;

    defined $action && grep ($_ eq $action, 'configure', 'deconfigure') or die( 'Missing or invalid $action parameter' );

    # Cleanup of configuration made by plugin versions < 2.2.0 (Debian <= 9)
    $self->_removeLegacyConfig();

    my $c = $self->{'config'};

    if ( $action eq 'configure' ) {
        debug( "Creating/Securing $c->{'opendkim_confdir'} directory" );
        $self->_secureConfDir();

        if ( my $socketDir = $self->_getSocketDir( $c->{'opendkim_socket'} ) ) {
            # The socket directory must be writable by the opendkim user (the
            # socket is created by opendkim(8) after dropping privileges). Its
            # parent directory must be root-owned so that the opendkim user
            # can't replace the directory with a symlink.
            debug( "Creating $socketDir OpenDKIM socket directory" );
            _secureDir( $socketDir, $c->{'opendkim_user'}, $c->{'opendkim_group'}, 0750 );
        }

        # (Re)build the TrustedHosts file
        my $file = iMSCP::File->new( filename => "$c->{'opendkim_confdir'}/TrustedHosts" );
        $file->set( join( "\n", @{$c->{'opendkim_trusted_hosts'}} ) . "\n" );
        $self->_saveFile( $file, 0640 );

        # (Re)build the KeyTable and SigningTable files from existing keys
        $self->_rebuildSigningTables();
    } else {
        if ( grep ( $_ eq $self->{'action'}, 'disable', 'uninstall' ) ) {
            debug( 'Stopping/Disabling OpenDKIM service' );
            my $serviceMngr = iMSCP::Service->getInstance();
            if ( $serviceMngr->hasService( 'opendkim' ) ) {
                $serviceMngr->stop( 'opendkim' );
                $serviceMngr->disable( 'opendkim' );
            }

            my $socketDir = $self->_getSocketDir( $self->{'config_prev'}->{'opendkim_socket'} );
            my $queueDir = Servers::mta->factory()->{'config'}->{'POSTFIX_QUEUE_DIR'} || '/var/spool/postfix';
            if ( defined $socketDir && index( $socketDir, "$queueDir/" ) == 0 && -d $socketDir ) {
                debug( "Removing $socketDir OpenDKIM socket directory" );
                iMSCP::Dir->new( dirname => $socketDir )->remove();
            }

            for ( qw/ KeyTable SigningTable TrustedHosts / ) {
                next unless -f "$self->{'config_prev'}->{'opendkim_confdir'}/$_";
                debug( "Removing $self->{'config_prev'}->{'opendkim_confdir'}/$_ file" );
                iMSCP::File->new( filename => "$self->{'config_prev'}->{'opendkim_confdir'}/$_" )->delFile() == 0 or die(
                    getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error'
                );
            }
        }
    }

    # /etc/opendkim.conf
    my $file = iMSCP::File->new( filename => '/etc/opendkim.conf' );
    my $fContent = -f $file->{'filename'} ? $file->get() : '';
    defined $fContent or die( sprintf( "Couldn't read %s file", $file->{'filename'} ));

    # Remove our configuration block and restore distribution settings
    $fContent = replaceBloc( "# Begin Plugin::OpenDKIM\n", "# Ending Plugin::OpenDKIM\n", '', $fContent );
    $fContent =~ s/^\Q$CONF_COMMENT_MARKER\E//gm;

    if ( $action eq 'configure' ) {
        debug( 'Updating OpenDKIM configuration' );

        # Comment out distribution settings that we override. Duplicate keys
        # are a source of confusion as only one of them is honored.
        my $keysRe = join '|', map { quotemeta } @MANAGED_CONF_KEYS;
        $fContent =~ s/^([\t ]*(?:$keysRe)[\t ]+)/$CONF_COMMENT_MARKER$1/gim;

        my $confdir = $c->{'opendkim_confdir'};
        $fContent .= <<"EOF";
# Begin Plugin::OpenDKIM
# Settings below are managed by the i-MSCP OpenDKIM plugin.
# Overridden distribution settings are commented out with the '$CONF_COMMENT_MARKER' prefix
# and restored when the plugin is deactivated.
Canonicalization    $c->{'opendkim_canonicalization'}
ExternalIgnoreList  $confdir/TrustedHosts
InternalHosts       $confdir/TrustedHosts
KeyTable            file:$confdir/KeyTable
LogWhy              no
MinimumKeyBits      1024
Mode                $c->{'opendkim_operating_mode'}
On-BadSignature     $c->{'opendkim_on_bad_signature'}
On-KeyNotFound      $c->{'opendkim_on_key_not_found'}
OversignHeaders     From
PidFile             /run/opendkim/opendkim.pid
RequireSafeKeys     yes
SignatureAlgorithm  rsa-sha256
SigningTable        file:$confdir/SigningTable
SoftwareHeader      yes
Socket              $c->{'opendkim_socket'}
Syslog              yes
SyslogSuccess       yes
UMask               007
UserID              $c->{'opendkim_user'}:$c->{'opendkim_group'}
# Ending Plugin::OpenDKIM
EOF
    }

    $file->set( $fContent );
    $file->save() == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );

    return unless $action eq 'configure';

    my $serviceTasksSub = sub {
        local $@;
        eval {
            debug( 'Enabling/Restarting OpenDKIM service' );
            my $serviceMngr = iMSCP::Service->getInstance();
            $serviceMngr->enable( 'opendkim' );
            $serviceMngr->restart( 'opendkim' );
        };
        if ( $@ ) {
            error( $@ );
            return 1;
        }
        0;
    };

    if ( defined $main::execmode && $main::execmode eq 'setup' ) {
        $self->{'eventManager'}->register(
            'beforeSetupRestartServices',
            sub {
                unshift @{$_[0]}, [ $serviceTasksSub, 'OpenDKIM' ];
                0;
            }
        ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
        return;
    }

    $serviceTasksSub->() == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
}

=item _removeLegacyConfig( )

 Remove configuration made by plugin versions < 2.2.0

 Return void, die on failure

=cut

sub _removeLegacyConfig
{
    my ($self) = @_;

    my $daemonReload = 0;

    # Block added in /etc/default/opendkim
    if ( -f '/etc/default/opendkim' ) {
        my $file = iMSCP::File->new( filename => '/etc/default/opendkim' );
        my $fContent = $file->get();
        defined $fContent or die( sprintf( "Couldn't read %s file", $file->{'filename'} ));
        if ( getBloc( "# Begin Plugin::OpenDKIM\n", "# Ending Plugin::OpenDKIM\n", $fContent, 1 ) ne '' ) {
            debug( 'Removing legacy configuration from /etc/default/opendkim' );
            $file->set( replaceBloc( "# Begin Plugin::OpenDKIM\n", "# Ending Plugin::OpenDKIM\n", '', $fContent ));
            $file->save() == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
        }
    }

    # systemd override.conf and tmpfiles.d files generated by older plugin
    # versions (rundir inside the Postfix queue directory)
    for my $legacyFile ( '/etc/systemd/system/opendkim.service.d/override.conf', '/etc/tmpfiles.d/opendkim.conf' ) {
        next unless -f $legacyFile;
        my $fContent = iMSCP::File->new( filename => $legacyFile )->get() // '';
        next unless $fContent =~ m%/var/spool/postfix|\{OPENDKIM_RUNDIR\}%;
        debug( "Removing legacy $legacyFile file" );
        iMSCP::File->new( filename => $legacyFile )->delFile() == 0 or die(
            getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error'
        );
        $daemonReload = 1;
    }

    if ( -d '/etc/systemd/system/opendkim.service.d'
        && iMSCP::Dir->new( dirname => '/etc/systemd/system/opendkim.service.d' )->isEmpty()
    ) {
        iMSCP::Dir->new( dirname => '/etc/systemd/system/opendkim.service.d' )->remove();
    }

    # Legacy rundir (plugin versions 2.0.x/2.1.x)
    for my $legacyDir ( '/var/spool/postfix/var/run/opendkim' ) {
        next unless -d $legacyDir;
        my $socketDir = $self->_getSocketDir( $self->{'config'}->{'opendkim_socket'} ) // '';
        next if $socketDir eq $legacyDir;
        debug( "Removing legacy $legacyDir directory" );
        iMSCP::Dir->new( dirname => $legacyDir )->remove();
    }

    if ( $daemonReload && iMSCP::Service->getInstance()->isSystemd() ) {
        iMSCP::Service->getInstance()->getProvider()->daemonReload();
    }
}

=item _postfixSetup( $action )

 Configure or deconfigure Postfix

 Only the OpenDKIM milter is added/removed in the smtpd_milters and
 non_smtpd_milters parameters. Milters from other components (ClamAV,
 SpamAssassin...) are left untouched. A per-milter default_action is used
 instead of the global milter_default_action parameter.

 Param string $action Action to perform (configure|deconfigure)
 Return void, die on failure

=cut

sub _postfixSetup
{
    my ($self, $action) = @_;

    defined $action && grep ($_ eq $action, 'configure', 'deconfigure') or die( 'Missing or invalid $action parameter' );

    debug( 'Removing OpenDKIM milter from Postfix configuration' );
    my %sockets = map { $_ => 1 } grep { defined } (
        $self->{'config_prev'}->{'postfix_milter_socket'},
        $self->{'config'}->{'postfix_milter_socket'},
        # Plugin versions < 2.0.0
        $self->{'config_prev'}->{'PostfixMilterSocket'}
    );
    # Match both the plain value and the per-milter settings form: { socket, ... }
    my @milterPrevValues = map { qr/^(?:\{\s*)?\Q$_\E(?:\s*[,}].*)?$/s } keys %sockets;
    my $mta = Servers::mta->factory();
    $mta->postconf(
        smtpd_milters     => { action => 'remove', values => [ @milterPrevValues ] },
        non_smtpd_milters => { action => 'remove', values => [ @milterPrevValues ] }
    ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );

    if ( $action eq 'deconfigure' ) {
        if ( grep ( $_ eq $self->{'action'}, 'disable', 'uninstall' ) ) {
            iMSCP::SystemUser->new()->removeFromGroup(
                $self->{'config_prev'}->{'opendkim_group'}, $mta->{'config'}->{'POSTFIX_USER'}
            ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
        }

        return if defined $main::execmode && $main::execmode eq 'setup';
        return unless $self->{'action'} eq 'disable';

        # On deactivation, we reload postfix immediately, as the OpenDKIM
        # service will become unavailable
        $mta->reload() == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
        return;
    }

    # Make the Postfix user able to connect to the OpenDKIM UNIX socket
    # (socket directory and socket are owned by the OpenDKIM group)
    iMSCP::SystemUser->new()->addToGroup(
        $self->{'config'}->{'opendkim_group'}, $mta->{'config'}->{'POSTFIX_USER'}
    ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );

    debug( 'Adding OpenDKIM milter in Postfix configuration' );
    my $milter = "{ $self->{'config'}->{'postfix_milter_socket'}, "
        . "default_action=$self->{'config'}->{'postfix_milter_default_action'} }";
    $mta->postconf(
        smtpd_milters     => { action => 'add', values => [ $milter ] },
        non_smtpd_milters => { action => 'add', values => [ $milter ] }
    ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
}

=item _addDomain( \%data )

 Enable OpenDKIM support for the given domain (generate key and add DKIM DNS record)

 Param hashref \%data Domain data
 Return void, die on failure

=cut

sub _addDomain
{
    my ($self, $data) = @_;

    # Subdomain entries are no longer used (ADSP has been removed)
    return if $data->{'is_subdomain'};

    my $domain = lc $data->{'domain_name'};
    $domain =~ $DOMAIN_NAME_RE or die( sprintf( 'Invalid domain name: %s', $data->{'domain_name'} ));

    my $c = $self->{'config'};
    my $keyDir = "$c->{'opendkim_confdir'}/keys/$domain";

    if ( $data->{'opendkim_status'} eq 'tochange' ) {
        # Key renewal; schedule deletion of current DNS record
        $self->_deleteDomainDnsRecord( $data );
    }

    my ($genkey) = grep { -x } @GENKEY_PATHS;
    defined $genkey or die( "Couldn't find the opendkim-genkey program. Is the opendkim-tools package installed?" );

    debug( "Creating OpenDKIM key directory for the $domain domain" );
    _secureDir( $keyDir, 0, $c->{'opendkim_group'}, 0750 );

    # Generate the key in a private root-owned temporary directory (never
    # inside a directory writable by the opendkim user), then move it in place
    my $tmpDir = File::Temp::tempdir( '.genkey-XXXXXXXX', DIR => $c->{'opendkim_confdir'}, CLEANUP => 0 );
    local $@;
    eval {
        debug( "Generating DKIM key for the $domain domain" );
        # List form: no shell involved
        my $stderr;
        execute(
            [ $genkey, '-b', $c->{'opendkim_keysize'}, '-h', 'sha256', '-r', '-s', 'mail', '-d', $domain, '-D', $tmpDir ],
            \my $stdout, \$stderr
        ) == 0 or die ( $stderr || 'Unknown error' );
        debug( $stdout ) if $stdout;

        # The private key is read by opendkim(8) (as the opendkim user). It
        # must not be group-readable (see RequireSafeKeys). The TXT record
        # file is only read by this backend.
        _secureFile( "$tmpDir/mail.private", $c->{'opendkim_user'}, $c->{'opendkim_group'}, 0600 );
        _secureFile( "$tmpDir/mail.txt", 0, $c->{'opendkim_group'}, 0640 );

        for ( qw/ mail.txt mail.private / ) {
            rename( "$tmpDir/$_", "$keyDir/$_" ) or die( sprintf( "Couldn't move %s to %s: %s", "$tmpDir/$_", "$keyDir/$_", $! ));
        }
    };
    my $err = $@;
    remove_tree( $tmpDir );
    die( $err ) if $err;

    $self->_addDomainSigningEntry( $domain );
    $self->_addDomainKeyEntry( $domain );

    my $file = iMSCP::File->new( filename => "$keyDir/mail.txt" );
    my $fContent = $file->get();
    defined $fContent or die( sprintf( "Couldn't read %s file", $file->{'filename'} ));
    # Strip the trailing zone file comment
    $fContent =~ s/\)\s*;.*$/)/s;

    # Extract all quoted <character-string>s, excluding delimiters
    $_ =~ s/^"(.*)"$/$1/s for my @txtRecordChunks = extract_multiple(
        $fContent, [ sub { extract_delimited( $_[0], '"' ) } ], undef, 1
    );

    my $txtRecord = join '', @txtRecordChunks;
    $txtRecord =~ s/\s+/ /g;
    $txtRecord =~ /^v=DKIM1;.*\bp=[A-Za-z0-9+\/=]+$/ or die( sprintf( "Couldn't parse %s file", $file->{'filename'} ));

    # Split data field into several <character-string>s when it is longer
    # than 255 bytes. See: https://tools.ietf.org/html/rfc7208#section-3.3
    undef @txtRecordChunks;
    for ( my $i = 0, my $length = length $txtRecord; $i < $length; $i += 255 ) {
        push @txtRecordChunks, substr( $txtRecord, $i, 255 );
    }
    $txtRecord = join ' ', map ( qq/"$_"/, @txtRecordChunks );

    debug( "Adding DKIM DNS record for the $domain domain" );
    local $self->{'dbh'}->{'RaiseError'} = 1;
    $self->{'dbh'}->do(
        "
            INSERT IGNORE INTO domain_dns (
                domain_id, alias_id, domain_dns, domain_class, domain_type, domain_text, owned_by, domain_dns_status
            ) VALUES (
                ?, ?, ?, 'IN', 'TXT', ?, 'OpenDKIM_Plugin', 'toadd'
            )
        ",
        undef, $data->{'domain_id'}, $data->{'alias_id'}, "mail._domainkey $c->{'opendkim_dns_records_ttl'}", $txtRecord
    );
}

=item _deleteDomain( \%data )

 Remove OpenDKIM support for the given domain

 Param hashref \%data Domain data
 Return void, die on failure

=cut

sub _deleteDomain
{
    my ($self, $data) = @_;

    unless ( $data->{'is_subdomain'} ) {
        my $domain = lc $data->{'domain_name'};
        $domain =~ $DOMAIN_NAME_RE or die( sprintf( 'Invalid domain name: %s', $data->{'domain_name'} ));

        debug( "Removing OpenDKIM key directory for the $domain domain" );
        iMSCP::Dir->new( dirname => "$self->{'config'}->{'opendkim_confdir'}/keys/$domain" )->remove();
        $self->_deleteDomainSigningEntry( $domain );
        $self->_deleteDomainKeyEntry( $domain );
    }

    $self->_deleteDomainDnsRecord( $data );
}

=item _deleteDomainDnsRecord( \%data )

 Schedule deletion of DKIM DNS records (including legacy ADSP records) for the given domain

 Param hashref \%data Domain data
 Return void, die on failure

=cut

sub _deleteDomainDnsRecord
{
    my ($self, $data) = @_;

    local $self->{'dbh'}->{'RaiseError'} = 1;

    if ( $data->{'is_subdomain'} ) {
        # Legacy ADSP record for subdomain
        $self->{'dbh'}->do(
            "
                UPDATE domain_dns SET domain_dns_status = 'todelete'
                WHERE domain_id = ? AND alias_id = ? AND domain_dns LIKE ? AND owned_by = 'OpenDKIM_Plugin'
            ",
            undef, $data->{'domain_id'}, $data->{'alias_id'}, "\\_adsp.\\_domainkey.$data->{'domain_name'}.%"
        );
        return;
    }

    debug( "Scheduling deletion of DKIM DNS record(s) for the $data->{'domain_name'} domain" );
    $self->{'dbh'}->do(
        "
            UPDATE domain_dns SET domain_dns_status = 'todelete'
            WHERE domain_id = ? AND alias_id = ? AND owned_by = 'OpenDKIM_Plugin'
        ",
        undef, $data->{'domain_id'}, $data->{'alias_id'}
    );
}

=item _addDomainSigningEntry( $domainName )

 Adds a domain signing entry in the signing table

 Messages from the domain and from any of its subdomains are signed with the
 domain key (d=<domain>).

 Param string $domainName Domain name
 Return void, die on failure

=cut

sub _addDomainSigningEntry
{
    my ($self, $domainName) = @_;

    debug( "Adding OpenDKIM signing entry for the $domainName domain" );
    my $file = iMSCP::File->new( filename => "$self->{'config'}->{'opendkim_confdir'}/SigningTable" );
    my $fContent = -f $file->{'filename'} ? $file->get() : '';
    defined $fContent or die( sprintf( "Couldn't read %s file", $file->{'filename'} ));
    $fContent =~ s/^\.?\Q$domainName\E\s[^\n]*\n//gm;
    $fContent .= "$domainName $domainName\n.$domainName .$domainName:\@%\n";
    $file->set( $fContent );
    $self->_saveFile( $file, 0640 );
}

=item _deleteDomainSigningEntry( $domainName )

 Deletes a domain signing entry from the signing table

 Param string $domainName Domain name
 Return void, die on failure

=cut

sub _deleteDomainSigningEntry
{
    my ($self, $domainName) = @_;

    my $file = iMSCP::File->new( filename => "$self->{'config'}->{'opendkim_confdir'}/SigningTable" );
    return unless -f $file->{'filename'};

    debug( "Deleting OpenDKIM signing entry for the $domainName domain" );
    my $fContent = $file->get();
    defined $fContent or die( sprintf( "Couldn't read %s file", $file->{'filename'} ));
    $file->set( $fContent =~ s/^\.?\Q$domainName\E\s[^\n]*\n//gmr );
    $self->_saveFile( $file, 0640 );
}

=item _addDomainKeyEntry( $domainName )

 Adds a domain key entry in the key table

 Param string $domainName Domain name
 Return void, die on failure

=cut

sub _addDomainKeyEntry
{
    my ($self, $domainName) = @_;

    debug( "Adding OpenDKIM key entry for the $domainName domain" );
    my $confdir = $self->{'config'}->{'opendkim_confdir'};
    my $file = iMSCP::File->new( filename => "$confdir/KeyTable" );
    my $fContent = -f $file->{'filename'} ? $file->get() : '';
    defined $fContent or die( sprintf( "Couldn't read %s file", $file->{'filename'} ));
    $fContent =~ s/^\.?\Q$domainName\E\s[^\n]*\n//gm;
    $fContent .= "$domainName %:mail:$confdir/keys/%/mail.private\n";
    $fContent .= ".$domainName $domainName:mail:$confdir/keys/$domainName/mail.private\n";
    $file->set( $fContent );
    $self->_saveFile( $file, 0640 );
}

=item _deleteDomainKeyEntry( $domainName )

 Deletes a domain key entry from the key table

 Param string $domainName Domain name
 Return void, die on failure

=cut

sub _deleteDomainKeyEntry
{
    my ($self, $domainName) = @_;

    my $file = iMSCP::File->new( filename => "$self->{'config'}->{'opendkim_confdir'}/KeyTable" );
    return unless -f $file->{'filename'};

    debug( "Deleting OpenDKIM key entry for the $domainName domain" );
    my $fContent = $file->get();
    defined $fContent or die( sprintf( "Couldn't read %s file", $file->{'filename'} ));
    # Fixed: was /^.?.../ (any char), which could match unrelated domains
    $file->set( $fContent =~ s/^\.?\Q$domainName\E\s[^\n]*\n//gmr );
    $self->_saveFile( $file, 0640 );
}

=item _rebuildSigningTables( )

 Rebuild the KeyTable and SigningTable files from existing keys

 Also removes the keys that belong to domains that were removed while the
 plugin was deactivated.

 Return void, die on failure

=cut

sub _rebuildSigningTables
{
    my ($self) = @_;

    my $confdir = $self->{'config'}->{'opendkim_confdir'};

    for ( qw/ KeyTable SigningTable / ) {
        my $file = iMSCP::File->new( filename => "$confdir/$_" );
        $file->set( '' );
        $self->_saveFile( $file, 0640 );
    }

    return unless -d "$confdir/keys";

    local $self->{'dbh'}->{'RaiseError'} = 1;
    my %domainNames = map { lc $_ => 1 } @{$self->{'dbh'}->selectcol_arrayref(
        "SELECT domain_name FROM opendkim WHERE is_subdomain = 0 AND opendkim_status <> 'todelete'"
    )};

    for my $domainName ( iMSCP::Dir->new( dirname => "$confdir/keys" )->getDirs() ) {
        # Never follow symlinks (see _secureConfDir())
        next if -l "$confdir/keys/$domainName";

        if ( $domainNames{lc $domainName} && $domainName =~ $DOMAIN_NAME_RE
            && !-l "$confdir/keys/$domainName/mail.private" && -f _
        ) {
            $self->_addDomainSigningEntry( $domainName );
            $self->_addDomainKeyEntry( $domainName );
            next;
        }

        next if $domainNames{lc $domainName}; # Key will be (re)generated
        debug( "Removing orphaned OpenDKIM key for the $domainName domain" );
        iMSCP::Dir->new( dirname => "$confdir/keys/$domainName" )->remove();
    }
}

=item _addMissingOpenDKIMEntries

 Add missing OpenDKIM entries in database

 This covers the case where, depending on context, a domain or domain alias
 has been added while the plugin was deactivated.

 Return void, die on failure

=cut

sub _addMissingOpenDKIMEntries
{
    my ($self) = @_;

    local $self->{'dbh'}->{'RaiseError'} = 1;

    my $rows = $self->{'config'}->{'plugin_working_level'} eq 'admin'
        ? $self->{'dbh'}->selectall_arrayref(
            "SELECT domain_id, domain_admin_id AS admin_id FROM domain WHERE domain_status <> 'todelete'", { Slice => {} }
        )
        : $self->{'dbh'}->selectall_arrayref(
            "SELECT admin_id, domain_id FROM opendkim WHERE opendkim_status <> 'todelete' GROUP BY admin_id, domain_id",
            { Slice => {} }
        );

    for my $row ( @{$rows} ) {
        local $@;
        eval {
            $self->{'dbh'}->begin_work();

            if ( $self->{'config'}->{'plugin_working_level'} eq 'admin' ) {
                debug( "Adding missing OpenDKIM entries for domains of customer with ID $row->{'admin_id'}" );
                $self->{'dbh'}->do(
                    "
                        INSERT IGNORE INTO opendkim (admin_id, domain_id, domain_name, opendkim_status)
                        SELECT domain_admin_id, domain_id, domain_name, 'toadd'
                        FROM domain
                        WHERE domain_id = ?
                        AND domain_status <> 'todelete'
                    ",
                    undef, $row->{'domain_id'}
                );
            }

            debug( "Adding missing OpenDKIM entries for domain aliases of customer with ID $row->{'admin_id'}" );
            $self->{'dbh'}->do(
                "
                    INSERT IGNORE INTO opendkim (admin_id, domain_id, alias_id, domain_name, opendkim_status)
                    SELECT ?, domain_id, alias_id, alias_name, 'toadd'
                    FROM domain_aliasses
                    WHERE domain_id = ?
                    AND alias_status NOT IN('todelete', 'ordered')
                ",
                undef, $row->{'admin_id'}, $row->{'domain_id'}
            );

            $self->{'dbh'}->commit();
        };
        if ( $@ ) {
            my $err = $@;
            $self->{'dbh'}->rollback();
            die( $err );
        }
    }

    $self->run() == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
}

=item _reloadOpendkim( )

 Reload OpenDKIM (re-read of configuration and tables)

 Return void, die on failure

=cut

sub _reloadOpendkim
{
    my ($self) = @_;

    # No need to reload when the service restart is delayed (setup)
    return if defined $main::execmode && $main::execmode eq 'setup';

    my $serviceMngr = iMSCP::Service->getInstance();
    return unless $serviceMngr->isRunning( 'opendkim' );
    $serviceMngr->reload( 'opendkim' );
}

=item _saveFile( $file, $mode )

 Save the given OpenDKIM file (root:<opendkim_group>, given mode)

 The file is written atomically (temporary file in the same root-owned
 directory, then rename(2)). A symlink planted in place of the file is
 replaced, never followed.

 Param iMSCP::File $file
 Param int $mode File mode
 Return void, die on failure

=cut

sub _saveFile
{
    my ($self, $file, $mode) = @_;

    _writeFileAtomic( $file->{'filename'}, $file->{'fileContent'} // '', 0, $self->{'config'}->{'opendkim_group'}, $mode );
}

=item _secureConfDir( )

 Create/secure the OpenDKIM configuration directory and the keys directory

 Ownership and permissions are (re)set as follows:
  <confdir>                        root:<opendkim_group>          0750
  <confdir>/keys                   root:<opendkim_group>          0750
  <confdir>/keys/<domain>          root:<opendkim_group>          0750
  <confdir>/keys/<domain>/mail.private  <opendkim_user>:<opendkim_group> 0600
  <confdir>/keys/<domain>/mail.txt root:<opendkim_group>          0640
  <confdir>/{KeyTable,SigningTable,TrustedHosts} root:<opendkim_group> 0640

 Older plugin versions made those directories owned by the opendkim user. The
 directories are secured top-down, so that once a directory is root-owned,
 the opendkim user can no longer plant entries in it. Symlinks are refused.

 Return void, die on failure

=cut

sub _secureConfDir
{
    my ($self) = @_;

    my $c = $self->{'config'};
    my $confdir = $c->{'opendkim_confdir'};
    $confdir =~ m%^/% or die( "The `opendkim_confdir' parameter must be an absolute path" );

    _secureDir( $confdir, 0, $c->{'opendkim_group'}, 0750 );
    _secureDir( "$confdir/keys", 0, $c->{'opendkim_group'}, 0750 );

    for my $entry ( qw/ KeyTable SigningTable TrustedHosts / ) {
        next unless lstat "$confdir/$entry";
        die( sprintf( 'Refusing to process %s: not a regular file (symlink?)', "$confdir/$entry" )) unless -f _;
        _secureFile( "$confdir/$entry", 0, $c->{'opendkim_group'}, 0640 );
    }

    opendir( my $dh, "$confdir/keys" ) or die( sprintf( "Couldn't open the %s directory: %s", "$confdir/keys", $! ));
    my @entries = grep { !/^\.{1,2}\z/s } readdir( $dh );
    closedir( $dh );

    for my $entry ( @entries ) {
        my $path = "$confdir/keys/$entry";
        lstat $path or next;
        die( sprintf( 'Refusing to process %s: symlink', $path )) if -l _;
        next unless -d _;

        _secureDir( $path, 0, $c->{'opendkim_group'}, 0750 );

        for ( [ 'mail.private', $c->{'opendkim_user'}, 0600 ], [ 'mail.txt', 0, 0640 ] ) {
            my $file = "$path/$_->[0]";
            lstat $file or next;
            die( sprintf( 'Refusing to process %s: not a regular file (symlink?)', $file )) unless -f _ && !-l _;
            _secureFile( $file, $_->[1], $c->{'opendkim_group'}, $_->[2] );
        }
    }
}

=back

=head1 FUNCTIONS (symlink-safe file operations)

=over 4

=item _ugid( $user, $group )

 Resolve the given user and group (names or numeric IDs)

 Return list (uid, gid), die on failure

=cut

sub _ugid
{
    my ($user, $group) = @_;

    my $uid = $user =~ /^\d+$/ ? $user : getpwnam( $user );
    my $gid = $group =~ /^\d+$/ ? $group : getgrnam( $group );
    defined $uid or die( sprintf( 'Unknown user: %s', $user ));
    defined $gid or die( sprintf( 'Unknown group: %s', $group ));
    ( $uid, $gid );
}

=item _assertTrustedDir( $dir )

 Make sure that no unprivileged user can replace any component of the given
 directory path (and so redirect a write made by root)

 Each path component must be owned by root. Ancestors must not be writable by
 group/others unless the sticky bit is set (the next component being
 root-owned, it can't be renamed/removed). The directory itself must not be
 writable by group (unless group is root) or others.

 Param string $dir Directory path
 Return void, die if the directory isn't trusted

=cut

sub _assertTrustedDir
{
    my ($dir) = @_;

    my $real = realpath( $dir );
    defined $real && -d $real or die( sprintf( "Couldn't resolve the %s directory: %s", $dir, $! || 'not a directory' ));

    my @components = grep { length } split m%/%, $real;
    my $path = '';
    for my $i ( -1 .. $#components ) {
        $path .= $i < 0 ? '/' : ( $i ? '/' : '' ) . $components[$i];
        my @st = lstat $path or die( sprintf( "Couldn't stat %s: %s", $path, $! ));
        die( sprintf( 'Untrusted path %s: %s is not owned by root', $dir, $path )) if $st[4] != 0;

        my $groupWritable = ( $st[2] & S_IWGRP ) && $st[5] != 0;
        my $otherWritable = $st[2] & S_IWOTH;
        next unless $groupWritable || $otherWritable;
        next if $i < $#components && ( $st[2] & S_ISVTX );
        die( sprintf( 'Untrusted path %s: %s is writable by non-root users', $dir, $path ));
    }
}

=item _secureDir( $dir, $user, $group, $mode )

 Create the given directory if needed, and set its ownership and permissions

 The parent directory must be trusted (see _assertTrustedDir()). Symlinks are
 refused. Ownership and permissions are set through a file descriptor opened
 with O_NOFOLLOW (no TOCTOU race).

 Param string $dir Directory path
 Param string|int $user Owner (name or UID)
 Param string|int $group Group (name or GID)
 Param int $mode Mode
 Return void, die on failure

=cut

sub _secureDir
{
    my ($dir, $user, $group, $mode) = @_;

    my ($uid, $gid) = _ugid( $user, $group );
    $dir =~ s%/+$%%;
    my $parent = dirname( $dir );

    unless ( -d $parent ) {
        # Missing parents are created root:root 0755
        iMSCP::Dir->new( dirname => $parent )->make( { user => 0, group => 0, mode => 0755 } );
    }

    _assertTrustedDir( $parent );

    unless ( lstat $dir ) {
        $!{'ENOENT'} or die( sprintf( "Couldn't stat %s: %s", $dir, $! ));
        mkdir( $dir, 0700 ) or $!{'EEXIST'} or die( sprintf( "Couldn't create the %s directory: %s", $dir, $! ));
        lstat $dir or die( sprintf( "Couldn't stat %s: %s", $dir, $! ));
    }

    die( sprintf( 'Refusing to process %s: symlink', $dir )) if -l _;
    die( sprintf( 'Refusing to process %s: not a directory', $dir )) unless -d _;
    my @lst = lstat _;

    sysopen( my $fh, $dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW ) or die(
        sprintf( "Couldn't open the %s directory: %s", $dir, $! )
    );
    my @st = stat $fh;
    $st[0] == $lst[0] && $st[1] == $lst[1] && S_ISDIR( $st[2] ) or die( sprintf( '%s has been replaced. Aborting.', $dir ));
    chown( $uid, $gid, $fh ) or die( sprintf( "Couldn't set ownership on %s: %s", $dir, $! ));
    chmod( $mode, $fh ) or die( sprintf( "Couldn't set permissions on %s: %s", $dir, $! ));
    close( $fh );
}

=item _secureFile( $file, $user, $group, $mode )

 Set ownership and permissions of the given regular file

 Symlinks and files with more than one hard link are refused. Ownership and
 permissions are set through a file descriptor opened with O_NOFOLLOW.

 Param string $file File path
 Param string|int $user Owner (name or UID)
 Param string|int $group Group (name or GID)
 Param int $mode Mode
 Return void, die on failure

=cut

sub _secureFile
{
    my ($file, $user, $group, $mode) = @_;

    my ($uid, $gid) = _ugid( $user, $group );

    sysopen( my $fh, $file, O_RDONLY | O_NOFOLLOW | O_NONBLOCK ) or die(
        sprintf( "Couldn't open %s: %s", $file, $! )
    );
    my @st = stat $fh;
    S_ISREG( $st[2] ) or die( sprintf( 'Refusing to process %s: not a regular file', $file ));
    $st[3] == 1 or die( sprintf( 'Refusing to process %s: file has several hard links', $file ));
    chown( $uid, $gid, $fh ) or die( sprintf( "Couldn't set ownership on %s: %s", $file, $! ));
    chmod( $mode, $fh ) or die( sprintf( "Couldn't set permissions on %s: %s", $file, $! ));
    close( $fh );
}

=item _writeFileAtomic( $file, $content, $user, $group, $mode )

 Write the given file atomically

 The content is written into a temporary file (O_EXCL, random name) created
 in the same, trusted, directory. Ownership and permissions are set through
 the file descriptor, then the file is renamed. Whatever was at the target
 path (including a symlink) is replaced, never followed.

 Param string $file File path
 Param string $content File content
 Param string|int $user Owner (name or UID)
 Param string|int $group Group (name or GID)
 Param int $mode Mode
 Return void, die on failure

=cut

sub _writeFileAtomic
{
    my ($file, $content, $user, $group, $mode) = @_;

    my ($uid, $gid) = _ugid( $user, $group );
    my $dir = dirname( $file );
    _assertTrustedDir( $dir );

    my $tmp = File::Temp->new( TEMPLATE => '.' . basename( $file ) . '.XXXXXXXX', DIR => $dir, UNLINK => 0 );
    my $tmpName = $tmp->filename();
    local $@;
    eval {
        binmode( $tmp );
        print { $tmp } $content or die( sprintf( "Couldn't write %s: %s", $tmpName, $! ));
        $tmp->flush() or die( sprintf( "Couldn't write %s: %s", $tmpName, $! ));
        chown( $uid, $gid, $tmp ) or die( sprintf( "Couldn't set ownership on %s: %s", $tmpName, $! ));
        chmod( $mode, $tmp ) or die( sprintf( "Couldn't set permissions on %s: %s", $tmpName, $! ));
        $tmp->close() or die( sprintf( "Couldn't close %s: %s", $tmpName, $! ));
        rename( $tmpName, $file ) or die( sprintf( "Couldn't rename %s to %s: %s", $tmpName, $file, $! ));
    };
    if ( my $err = $@ ) {
        unlink( $tmpName );
        die( $err );
    }
}

=back

=head1 AUTHORS

 Laurent Declercq <l.declercq@nuxwin.com>
 Rene Schuster <mail@reneschuster.de>
 Sascha Bay <info@space2place.de>

=cut

1;
__END__
