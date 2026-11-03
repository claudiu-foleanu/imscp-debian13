=head1 NAME

 Plugin::ClamAV

=cut

# i-MSCP ClamAV plugin
# Copyright (C) 2014-2017 Laurent Declercq <l.declercq@nuxwin.com>
# Copyright (C) 2013-2017 Rene Schuster <mail@reneschuster.de>
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

package Plugin::ClamAV;

use strict;
use warnings;
use autouse 'iMSCP::Debug' => qw/ debug error /;
use autouse 'iMSCP::Execute' => qw/ execute /;
use autouse 'iMSCP::TemplateParser' => qw/ getBloc process replaceBloc /;
use Class::Autouse qw/ :nostat iMSCP::Dir iMSCP::File iMSCP::Service Servers::mta /;
use Cwd qw/ realpath /;
use Fcntl qw/ O_RDONLY O_WRONLY O_CREAT O_APPEND O_NOFOLLOW O_NONBLOCK O_DIRECTORY S_ISDIR S_ISREG S_ISVTX S_IWGRP S_IWOTH /;
use File::Basename qw/ basename dirname /;
use File::Temp ();
use parent 'Common::SingletonClass';

# clamav-unofficial-sigs script location. Older plugin versions installed it
# into /usr/local/bin.
my $CUS_SCRIPT = '/usr/local/sbin/clamav-unofficial-sigs.sh';
my $CUS_SCRIPT_OLD = '/usr/local/bin/clamav-unofficial-sigs.sh';
my $CUS_CONF_DIR = '/etc/clamav-unofficial-sigs';
my $CUS_WORK_DIR = '/var/lib/clamav-unofficial-sigs';
my $CUS_LOG_DIR = '/var/log/clamav-unofficial-sigs';
our $CLAMAV_MILTER_CONF = '/etc/clamav/clamav-milter.conf';
our $CLAMD_CONF = '/etc/clamav/clamd.conf';
# Marker used to comment out distribution clamd.conf(5) settings that are
# overridden by this plugin. Those lines are restored on deactivation.
my $CLAMD_CONF_COMMENT_MARKER = '#Plugin::ClamAV# ';
# clamd.conf(5) settings managed by this plugin (also clamav-daemon debconf keys)
my @CLAMD_MANAGED_KEYS = qw/ LocalSocketGroup LocalSocketMode /;
# systemd drop-in files installed by this plugin
our $SYSTEMD_UNIT_DIR = '/etc/systemd/system';
my $SYSTEMD_DROPIN_FILENAME = 'imscp-plugin-clamav.conf';
# Unprivileged user/group as which the clamav-unofficial-sigs script is run
# (must match the clam_user/clam_group values in os.conf)
my $CUS_USER = 'clamav';
my $CUS_GROUP = 'clamav';
# Files installed by this plugin for clamav-unofficial-sigs (root-owned)
my $CUS_CRON_FILE = '/etc/cron.d/clamav-unofficial-sigs';
my $CUS_LOGROTATE_FILE = '/etc/logrotate.d/clamav-unofficial-sigs';
my $CUS_MAN_FILE = '/usr/share/man/man8/clamav-unofficial-sigs.8';
my $CUS_LOG_FILE = "$CUS_LOG_DIR/clamav-unofficial-sigs.log";
# Official ClamAV databases (managed by freshclam), never purged
my @CLAMAV_OFFICIAL_DBS = qw/ main daily bytecode freshclam /;

=head1 DESCRIPTION

 i-MSCP ClamAV plugin backend.

 Security notes:
  - The clamav-unofficial-sigs script is never run as root. It is run as the
    clamav user (signatures update), exactly like the cron task. The parts
    that require root privileges (working/log directories, cron and logrotate
    files) are done by this backend, with root-owned sources.
  - On deactivation, the third-party databases listed in the purge.txt file
    (written by the clamav user) are removed only if they are regular files
    located directly in the ClamAV database directory.

=head1 PUBLIC METHODS

=over 4

=item install( )

 Perform install tasks

 Return int 0 on success, other on failure

=cut

sub install
{
    my ( $self ) = @_;

    my $rs = $self->_installDistributionPackages();
    $rs ||= $self->_initClamAVdatabases();
    $rs ||= $self->_installClamavUnofficialSigs();
}

=item uninstall( )

 Perform uninstall tasks

 Return int 0 on success, other on failure

=cut

sub uninstall
{
    $_[0]->_removeClamavUnofficialSigs();
}

=item update( )

 Perform update tasks

 Return int 0 on success, other on failure

=cut

sub update
{
    $_[0]->install();
}

=item enable( )

 Perform enable tasks

 Return int 0 on success, other on failure

=cut

sub enable
{
    my ( $self ) = @_;

    my $rs = $self->_configureClamd( 'configure' );
    $rs ||= $self->_configureClamavMilter( 'configure' );
    $rs ||= $self->_configurePostfix( 'configure' );
    return $rs if $rs;

    my $serviceTasksSub = sub {
        local $@;
        eval {
            my $serviceMngr = iMSCP::Service->getInstance();
            $serviceMngr->enable( 'clamav-freshclam' );
            $serviceMngr->restart( 'clamav-freshclam' );

            $serviceMngr->enable( 'clamav-daemon' );
            if ( _hasClamdSocketUnit() ) {
                # The clamd socket is created by systemd (socket activation),
                # and clamd(8) then ignores the LocalSocketMode/Group settings.
                # The socket unit must be restarted for the SocketMode/Group
                # settings to be applied, and it can't be while the service is
                # running. The socket is stopped first, else a connection
                # could activate the service again in the meantime.
                _systemctlSocket( 'stop' );
                $serviceMngr->stop( 'clamav-daemon' );
                _systemctlSocket( 'start' );
                $serviceMngr->start( 'clamav-daemon' );
            } else {
                $serviceMngr->restart( 'clamav-daemon' );
            }

            $serviceMngr->enable( 'clamav-milter' );
            $serviceMngr->getProvider()->setPidPattern( 'clamav-milter' );
            $serviceMngr->restart( 'clamav-milter' );
        };
        if ( $@ ) {
            error( $@ );
            return 1;
        }

        # The unofficial signatures script reloads clamd, hence it must be
        # run once clamd is up.
        $self->_configureClamavUnofficialSigs( 'configure' );
    };

    if ( defined $::execmode && $::execmode eq 'setup' ) {
        return $self->{'eventManager'}->register(
            'beforeSetupRestartServices',
            sub {
                unshift @{ $_[0] }, [ $serviceTasksSub, 'ClamAV' ];
                0;
            }
        );
    }

    $serviceTasksSub->();
}

=item disable( )

 Perform disable tasks

 Return int 0 on success, other on failure

=cut

sub disable
{
    my ( $self ) = @_;

    # On plugin deactivation, the clamav-unofficial-sigs cron task and the
    # third-party databases are removed as ClamAV services are stopped. On
    # plugin change/update, only the user configuration file is removed.
    my $rs = $self->{'action'} eq 'disable'
        ? $self->_disableClamavUnofficialSigs() : $self->_configureClamavUnofficialSigs( 'deconfigure' );
    $rs ||= $self->_configurePostfix( 'deconfigure' );
    $rs ||= $self->_configureClamavMilter( 'deconfigure' );
    $rs ||= $self->_configureClamd( 'deconfigure' );
    return $rs if $rs || $self->{'action'} ne 'disable';

    # The ClamAV milter is about to be stopped. Make Postfix aware of the
    # change immediately, else, mails would be deferred until the next
    # Postfix reload
    unless ( defined $::execmode && $::execmode eq 'setup' ) {
        $rs = Servers::mta->factory()->reload();
        return $rs if $rs;
    }

    local $@;
    eval {
        my $serviceMngr = iMSCP::Service->getInstance();

        $serviceMngr->getProvider()->setPidPattern( 'clamav-milter' );
        $serviceMngr->stop( 'clamav-milter' );
        $serviceMngr->disable( 'clamav-milter' );

        for my $service ( qw/ clamav-daemon clamav-freshclam / ) {
            $serviceMngr->stop( $service );
            $serviceMngr->disable( $service );
        }

        # Else, clamd would be socket-activated again on the next connection
        _systemctlSocket( 'stop' ) if _hasClamdSocketUnit();
    };
    if ( $@ ) {
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

 Return Plugin::ClamAV or die on failure

=cut

sub _init
{
    my ( $self ) = @_;

    for my $param ( qw/ PostfixMilterSocket clamav_milter_options clamav_unofficial_sigs_options / ) {
        exists $self->{'config'}->{$param} or die( sprintf(
            'Missing %s configuration parameter', $param
        ));
    }

    $self->{'config'}->{'PostfixMilterDefaultAction'} //= 'tempfail';
    $self->{'config'}->{'PostfixMilterDefaultAction'} =~ /^(?:accept|reject|tempfail|quarantine)$/ or die(
        "Invalid value for the 'PostfixMilterDefaultAction' configuration parameter"
    );

    # clamd socket settings (parameter added in a later plugin version)
    my $clamdOptions = $self->{'config'}->{'clamd_options'} //= {};
    ref $clamdOptions eq 'HASH' or die( "Invalid value for the 'clamd_options' configuration parameter" );
    $clamdOptions->{'LocalSocketGroup'} //= 'clamav';
    $clamdOptions->{'LocalSocketMode'} //= '660';
    $clamdOptions->{'LocalSocketGroup'} =~ /^[a-z_][a-z0-9_-]{0,31}\z/ or die(
        "Invalid value for the 'clamd_options' LocalSocketGroup configuration parameter"
    );
    $clamdOptions->{'LocalSocketMode'} =~ /^0?([0-7]{3})\z/ or die(
        "Invalid value for the 'clamd_options' LocalSocketMode configuration parameter. Octal mode expected."
    );
    $clamdOptions->{'LocalSocketMode'} = $1;
    oct( $clamdOptions->{'LocalSocketMode'} ) & 07 and die(
        "Invalid value for the 'clamd_options' LocalSocketMode configuration parameter: the clamd socket must not "
            . "be accessible to other users (e.g. 660)"
    );
    ( oct( $clamdOptions->{'LocalSocketMode'} ) & 0600 ) == 0600 or die(
        "Invalid value for the 'clamd_options' LocalSocketMode configuration parameter: the clamd socket must be "
            . "readable and writable by its owner (e.g. 660)"
    );
    for my $option ( keys %{ $clamdOptions } ) {
        grep { $option eq $_ } @CLAMD_MANAGED_KEYS or die( sprintf(
            "Unsupported '%s' clamd_options configuration parameter", $option
        ));
    }

    $self;
}

=item _installClamavUnofficialSigs( )

 Install clamav-unofficial-sigs

 Return int 0 on success, other on failure

=cut

sub _installClamavUnofficialSigs
{
    if ( -f $CUS_SCRIPT_OLD ) {
        my $rs = iMSCP::File->new( filename => $CUS_SCRIPT_OLD )->delFile();
        return $rs if $rs;
    }

    my $file = iMSCP::File->new(
        filename => "$::imscpConfig{'PLUGINS_DIR'}/ClamAV/clamav-unofficial-sigs/clamav-unofficial-sigs.sh"
    );
    my $rs = $file->copyFile( $CUS_SCRIPT, { preserve => 'no' } );
    return $rs if $rs;

    $file->{'filename'} = $CUS_SCRIPT;
    $rs = $file->owner( $::imscpConfig{'ROOT_USER'}, $::imscpConfig{'ROOT_GROUP'} );
    $rs ||= $file->mode( 0755 );
}

=item _removeClamavUnofficialSigs( )

 Remove clamav-unofficial-sigs

 Return int 0 on success, other on failure

=cut

sub _removeClamavUnofficialSigs
{
    my ( $self ) = @_;

    my $rs = $self->_disableClamavUnofficialSigs();
    return $rs if $rs;

    for my $script ( $CUS_SCRIPT, $CUS_SCRIPT_OLD ) {
        next unless -f $script;
        $rs = iMSCP::File->new( filename => $script )->delFile();
        return $rs if $rs;
    }

    0;
}

=item _configureClamavUnofficialSigs( [ $action = 'deconfigure' ] )

 Configure or deconfigure clamav-unofficial-sigs

 Param string $action Action to be performed (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureClamavUnofficialSigs
{
    my ( $self, $action ) = @_;
    $action //= 'deconfigure';

    if ( $action eq 'configure' ) {
        unless ( $self->{'config'}->{'clamav_unofficial_sigs_options'}->{'clamav_unofficial_sigs'} eq 'yes' ) {
            return $self->_disableClamavUnofficialSigs();
        }

        unless ( -x $CUS_SCRIPT ) {
            my $rs = $self->_installClamavUnofficialSigs();
            return $rs if $rs;
        }

        my $rs = $self->_configureClamavUnofficialSigsConffile( 'master.conf' );
        $rs ||= $self->_configureClamavUnofficialSigsConffile( 'os.conf' );
        $rs ||= $self->_configureClamavUnofficialSigsConffile( 'user.conf' );
        return $rs if $rs;

        # Working and log directories, cron and logrotate files. This was
        # previously done by running the script as root (--install-all),
        # which followed symlinks in the clamav-writable directories.
        $rs = $self->_setupClamavUnofficialSigsFiles();
        return $rs if $rs;

        # First signatures update (silent mode), as the unprivileged clamav
        # user (same as the cron task), with a clean environment
        $rs = execute(
            [
                'runuser', '-u', $CUS_USER, '--', 'env', '-i',
                'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', "HOME=$CUS_WORK_DIR", 'LANG=C',
                '/bin/bash', $CUS_SCRIPT, '--silence'
            ],
            \my $stdout,
            \my $stderr
        );
        debug( $stdout ) if length $stdout;
        error( sprintf(
            "Couldn't update ClamAV unofficial signatures: %s", $stderr || $stdout || 'Unknown error'
        )) if $rs;
        return $rs;
    }

    return 0 unless -f "$CUS_CONF_DIR/user.conf";

    # Remove user.conf file for deactivation
    iMSCP::File->new( filename => "$CUS_CONF_DIR/user.conf" )->delFile();
}

=item _setupClamavUnofficialSigsFiles( )

 Create the clamav-unofficial-sigs working and log directories, and install
 the cron and logrotate files

 Ownership:
  /var/lib/clamav-unofficial-sigs                    clamav:clamav 0755
  /var/log/clamav-unofficial-sigs                    root:root     0755
  /var/log/clamav-unofficial-sigs/*.log              clamav:adm    0640
  /etc/cron.d/clamav-unofficial-sigs                 root:root     0644
  /etc/logrotate.d/clamav-unofficial-sigs            root:root     0644

 Return int 0 on success, other on failure

=cut

sub _setupClamavUnofficialSigsFiles
{
    local $@;
    eval {
        _secureDir( $CUS_WORK_DIR, $CUS_USER, $CUS_GROUP, 0755 );

        # The log directory stays root-owned (logrotate(8) runs as root in it).
        # Only the log file is owned by the clamav user.
        _secureDir( $CUS_LOG_DIR, 0, 0, 0755 );
        my $logGroup = getgrnam( 'adm' ) ? 'adm' : $CUS_GROUP;
        sysopen( my $fh, $CUS_LOG_FILE, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0640 ) or die(
            sprintf( "Couldn't open %s: %s", $CUS_LOG_FILE, $! )
        );
        close( $fh );
        _secureFile( $CUS_LOG_FILE, $CUS_USER, $logGroup, 0640 );

        my $minute = int( rand( 60 ));
        _writeFileAtomic( $CUS_CRON_FILE, <<"EOT", 0, 0, 0644 );
# clamav-unofficial-sigs cron task
# Auto-generated by the i-MSCP ClamAV plugin
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
#
# The script is run as the unprivileged $CUS_USER user.
$minute * * * * $CUS_USER [ -x $CUS_SCRIPT ] && /bin/bash $CUS_SCRIPT >/dev/null 2>&1
EOT

        _writeFileAtomic( $CUS_LOGROTATE_FILE, <<"EOT", 0, 0, 0644 );
# clamav-unofficial-sigs logrotate configuration
# Auto-generated by the i-MSCP ClamAV plugin
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
$CUS_LOG_FILE {
  weekly
  rotate 4
  missingok
  notifempty
  compress
  create 0640 $CUS_USER $logGroup
}
EOT
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _configureClamavUnofficialSigsConffile( $confFile )

 Configure the given clamav-unofficial-sigs config files

 Param string $confFile Configuration filename
 Return int 0 on success, other on failure

=cut

sub _configureClamavUnofficialSigsConffile
{
    my ( $self, $confFile ) = @_;

    local $@;
    eval {
        iMSCP::Dir->new( dirname => $CUS_CONF_DIR )->make( {
            user  => $::imscpConfig{'ROOT_USER'},
            group => $::imscpConfig{'ROOT_GROUP'},
            mode  => 0755
        } );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    my $file = iMSCP::File->new(
        filename => "$::imscpConfig{'PLUGINS_DIR'}/ClamAV/clamav-unofficial-sigs/config/$confFile"
    );
    my $fileContent = $file->get();
    unless ( defined $fileContent ) {
        error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
        return 1;
    }

    if ( $confFile eq 'user.conf' ) {
        my $options = $self->{'config'}->{'clamav_unofficial_sigs_options'};
        my $configSnippet = '';

        for my $section (
            [ 'MalwarePatrol options', 'malwarepatrol_options' ],
            [ 'SecuriteInfo options', 'securiteinfo_options' ],
            [ 'Signatures enabled', 'signatures_enabled' ],
            [ 'Rating options', 'rating_options' ]
        ) {
            next unless ref $options->{$section->[1]} eq 'HASH';
            $configSnippet .= "\n" if length $configSnippet;
            $configSnippet .= "# $section->[0]\n";
            for my $option ( sort keys %{ $options->{$section->[1]} } ) {
                # Sanitize both names and values as the file is sourced by bash(1)
                unless ( $option =~ /^[a-z0-9_]+$/ ) {
                    error( sprintf( 'Invalid clamav-unofficial-sigs option name: %s', $option ));
                    return 1;
                }

                my $value = $options->{$section->[1]}->{$option} // '';
                unless ( $value =~ /^[A-Za-z0-9_.\-]*$/ ) {
                    error( sprintf( 'Invalid value for the %s clamav-unofficial-sigs option', $option ));
                    return 1;
                }

                $configSnippet .= "$option=\"$value\"\n";
            }
        }

        $fileContent = process( { USER_CONFIGURATION => $configSnippet }, $fileContent );
    }

    $file->{'filename'} = "$CUS_CONF_DIR/$confFile";
    $file->set( $fileContent );
    my $rs = $file->save();
    $rs ||= $file->owner( $::imscpConfig{'ROOT_USER'}, $::imscpConfig{'ROOT_GROUP'} );
    $rs ||= $file->mode( 0644 );
}

=item _disableClamavUnofficialSigs( )

 Disable clamav-unofficial-sigs

 Return int 0 on success, other on failure

=cut

sub _disableClamavUnofficialSigs
{
    return 0 unless -d $CUS_WORK_DIR;

    # Root-owned files installed by this plugin (or by older plugin versions)
    for my $file ( $CUS_CRON_FILE, $CUS_LOGROTATE_FILE, $CUS_MAN_FILE ) {
        next unless -f $file || -l $file;
        my $rs = iMSCP::File->new( filename => $file )->delFile();
        return $rs if $rs;
    }

    # Third-party databases installed by the script
    local $@;
    eval {
        _purgeClamavUnofficialSigsDatabases( "$CUS_WORK_DIR/configs/purge.txt", '/var/lib/clamav' );

        # File::Path::remove_tree() doesn't follow symlinks
        iMSCP::Dir->new( dirname => $_ )->remove() for $CUS_CONF_DIR, $CUS_WORK_DIR, $CUS_LOG_DIR;
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    # Make clamd aware of removed databases
    if ( iMSCP::Service->getInstance()->hasService( 'clamav-daemon' ) ) {
        eval {
            my $serviceMngr = iMSCP::Service->getInstance();
            $serviceMngr->reload( 'clamav-daemon' ) if $serviceMngr->isRunning( 'clamav-daemon' );
        };
        if ( $@ ) {
            error( $@ );
            return 1;
        }
    }

    0;
}

=item _purgeClamavUnofficialSigsDatabases( $purgeFile, $dbDir )

 Remove the third-party databases listed in the given purge file

 The purge file is written by the clamav user, hence its content is
 untrusted. Only entries of the form <dbDir>/<filename> are honored, and only
 if they are regular files (no subdirectory, no symlink, no official
 database). unlink(2) never follows a symlink in the last path component, and
 the database directory itself must be a real directory in a root-owned
 parent, so that it can't be redirected elsewhere.

 Param string $purgeFile Purge file path
 Param string $dbDir ClamAV database directory
 Return void, die on failure

=cut

sub _purgeClamavUnofficialSigsDatabases
{
    my ($purgeFile, $dbDir) = @_;

    return unless lstat $purgeFile;
    return unless -f _; # Refuse symlinks and special files

    lstat $dbDir or return;
    die( sprintf( 'Refusing to purge databases: %s is not a directory (symlink?)', $dbDir )) unless -d _ && !-l _;
    _assertTrustedDir( dirname( $dbDir ));

    sysopen( my $fh, $purgeFile, O_RDONLY | O_NOFOLLOW | O_NONBLOCK ) or die(
        sprintf( "Couldn't open %s: %s", $purgeFile, $! )
    );
    my %seen;
    while ( my $path = <$fh> ) {
        $path =~ s/^\s+|\s+$//g;
        next unless length $path;

        # Only "<dbDir>/<filename>" entries, where filename is a plain name
        my ($name) = $path =~ m%^\Q$dbDir\E/+([A-Za-z0-9][A-Za-z0-9._-]*)$% or next;
        next if $seen{$name}++;
        next if grep { $name =~ /^\Q$_\E\./ } @CLAMAV_OFFICIAL_DBS;

        my $file = "$dbDir/$name";
        lstat $file or next;
        next unless -f _; # Not a regular file (symlink, directory...)
        unlink( $file ) or die( sprintf( "Couldn't remove %s: %s", $file, $! ));
        debug( sprintf( 'Removed the %s third-party ClamAV database', $file ));
    }
    close( $fh );
}

=item _configureClamavMilter( [ $action = 'deconfigure' ] )

 Configure or deconfigure clamav-milter

 Param string $action Action to be performed (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureClamavMilter
{
    my ( $self, $action ) = @_;
    $action //= 'deconfigure';

    return 0 if !-f $CLAMAV_MILTER_CONF && $action eq 'deconfigure';

    unless ( -f _ ) {
        error( sprintf( 'File %s not found', $CLAMAV_MILTER_CONF ));
        return 1;
    }

    my $file = iMSCP::File->new( filename => $CLAMAV_MILTER_CONF );
    my $fileContent = $file->get();
    unless ( defined $fileContent ) {
        error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
        return 1;
    }

    my $options = $self->{'config'}->{'clamav_milter_options'};
    my $optionReg = '((?:' . ( join '|', map( quotemeta, keys %{ $options } ) ) . ')\b.*)';

    # Remove our previous configuration block (if any) and restore default
    # configuration options which were disabled by us
    $fileContent = replaceBloc( "# Begin Plugin::ClamAV\n", "# Ending Plugin::ClamAV\n", '', $fileContent );
    $fileContent =~ s/^#$optionReg/$1/gm;

    if ( $action eq 'configure' ) {
        # Disable default configuration options (those that we want redefine)
        $fileContent =~ s/^$optionReg/#$1/gm;

        my $configSnippet = "# Begin Plugin::ClamAV\n";
        for my $option ( sort keys %{ $options } ) {
            next unless defined $options->{$option} && $options->{$option} ne '';
            if ( $option !~ /^[A-Za-z]+$/ || $options->{$option} =~ /[\r\n]/ ) {
                error( sprintf( 'Invalid clamav-milter option: %s', $option ));
                return 1;
            }
            $configSnippet .= "$option $options->{$option}\n";
        }
        $configSnippet .= "# Ending Plugin::ClamAV\n";

        $fileContent .= $configSnippet;
    }

    $file->set( $fileContent );
    my $rs = $file->save();
    return $rs if $rs || $action ne 'configure';

    # Make sure that the milter socket directory exists in the Postfix chroot
    # (clamav-milter init script also creates it, but only at start time)
    my $socket = $options->{'MilterSocket'} // '';
    $socket =~ s/^(?:unix|local)://;
    return 0 unless index( $socket, '/' ) == 0;

    ( my $socketDir = $socket ) =~ s%/[^/]+$%%;
    local $@;
    eval {
        # The socket directory is owned by the clamav-milter user (the socket
        # itself is created by clamav-milter(8) with the MilterSocketGroup
        # group and the MilterSocketMode mode). Symlinks are refused and the
        # parent directory must be root-owned.
        my $user = $options->{'User'} || 'clamav';
        _secureDir( $socketDir, $user, ( getpwnam( $user ) )[3] // $user, 0755 );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _configureClamd( [ $action = 'deconfigure' ] )

 Configure or deconfigure clamd (socket access)

 The clamd socket gives full control over the ClamAV daemon (SHUTDOWN, RELOAD,
 SCAN of any file readable by clamd...). Debian makes it world-accessible by
 default (LocalSocketMode 666), meaning that any local user, including
 customer CGI scripts, could shut down clamd and stall all mails (clamav-milter
 OnFail Defer). This method:
  - sets the LocalSocketGroup and LocalSocketMode settings in clamd.conf(5).
    Overridden distribution settings are commented out (and restored on
    deactivation);
  - syncs the clamav-daemon debconf answers, so that the values are kept when
    the clamav-daemon postinst script regenerates the clamd.conf file
    (package upgrade, dpkg-reconfigure);
  - installs systemd drop-in files: SocketGroup/SocketMode for the
    clamav-daemon.socket unit (with socket activation, the socket is created
    by systemd and clamd(8) ignores the clamd.conf settings), and
    Restart=on-failure for the clamav-daemon and clamav-milter services.

 Param string $action Action to be performed (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureClamd
{
    my ( $self, $action ) = @_;
    $action //= 'deconfigure';

    local $@;
    eval {
        if ( lstat $CLAMD_CONF ) {
            -f _ && !-l _ or die( sprintf( 'Refusing to process %s: not a regular file', $CLAMD_CONF ));
            $self->_assertClamdSocketAccess() if $action eq 'configure';

            my $file = iMSCP::File->new( filename => $CLAMD_CONF );
            my $content = $file->get();
            defined $content or die( sprintf( "Couldn't read the %s file", $CLAMD_CONF ));

            my $newContent = $self->_renderClamdConf( $content, $action );
            _writeFileAtomic( $CLAMD_CONF, $newContent, 0, 0, 0644 ) if $newContent ne $content;
            $self->_syncClamdDebconf( $newContent );
        } elsif ( $action eq 'configure' ) {
            die( sprintf( 'File %s not found', $CLAMD_CONF ));
        }

        $self->_configureClamdSystemd( $action );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _renderClamdConf( $content, $action )

 Render the clamd.conf(5) file content for the given action

 Param string $content Current clamd.conf file content
 Param string $action Action to be performed (configure|deconfigure)
 Return string New clamd.conf file content

=cut

sub _renderClamdConf
{
    my ( $self, $content, $action ) = @_;

    # Remove our configuration block (if any) and restore distribution settings
    $content = replaceBloc( "# Begin Plugin::ClamAV\n", "# Ending Plugin::ClamAV\n", '', $content );
    $content =~ s/^\Q$CLAMD_CONF_COMMENT_MARKER\E//gm;
    return $content unless $action eq 'configure';

    # Comment out distribution settings that we override. Only the first
    # occurrence is honored by the clamav-daemon debconf config script.
    my $keysRe = join '|', map { quotemeta } @CLAMD_MANAGED_KEYS;
    $content =~ s/^([\t ]*(?:$keysRe)(?:[\t ]|$))/$CLAMD_CONF_COMMENT_MARKER$1/gim;

    $content .= "\n" if length $content && $content !~ /\n\z/;
    $content .= "# Begin Plugin::ClamAV\n"
        . "# Settings below are managed by the i-MSCP ClamAV plugin. Overridden distribution settings\n"
        . "# are commented out with the '$CLAMD_CONF_COMMENT_MARKER' prefix and restored when the plugin is deactivated.\n";
    my $options = $self->{'config'}->{'clamd_options'};
    for my $option ( @CLAMD_MANAGED_KEYS ) {
        # Last line of defense against configuration injection (see _init())
        $options->{$option} =~ /^[A-Za-z0-9_-]+\z/ or die( sprintf( 'Invalid clamd %s option', $option ));
        $content .= "$option $options->{$option}\n";
    }
    $content . "# Ending Plugin::ClamAV\n";
}

=item _assertClamdSocketAccess( )

 Make sure that the clamav-milter user will be able to connect to clamd

 Return void, die on failure

=cut

sub _assertClamdSocketAccess
{
    my ( $self ) = @_;

    my $group = $self->{'config'}->{'clamd_options'}->{'LocalSocketGroup'};
    my @gr = getgrnam( $group ) or die( sprintf( 'Unknown clamd LocalSocketGroup group: %s', $group ));
    my $user = $self->{'config'}->{'clamav_milter_options'}->{'User'} || 'clamav';
    my @pw = getpwnam( $user ) or die( sprintf( 'Unknown clamav-milter user: %s', $user ));

    # The socket is owned by the clamav user (clamd User / SocketUser)
    return if $pw[2] == 0 || $user eq 'clamav';

    my $mode = oct( $self->{'config'}->{'clamd_options'}->{'LocalSocketMode'} );
    return if ( $mode & 060 ) == 060 && ( $pw[3] == $gr[2] || grep { $_ eq $user } split /\s+/, $gr[3] );

    die( sprintf(
        "The clamav-milter user (%s) couldn't connect to clamd: it must be a member of the clamd LocalSocketGroup "
            . "group (%s) and the LocalSocketMode mode must give read/write permissions to that group.",
        $user, $group
    ));
}

=item _syncClamdDebconf( $content )

 Sync the clamav-daemon debconf answers with the given clamd.conf content

 The clamav-daemon postinst script regenerates the clamd.conf file from the
 debconf answers. Its config script first stores the active clamd.conf values
 as debconf answers, but syncing them here ensures that the database is
 coherent whatever happens (dpkg-reconfigure, reinstallation...).

 Param string $content clamd.conf file content
 Return void, die on failure

=cut

sub _syncClamdDebconf
{
    my ( undef, $content ) = @_;

    my ( $cmd ) = grep { -x } qw( /usr/bin/debconf-set-selections /bin/debconf-set-selections );
    return unless defined $cmd;

    my $selections = '';
    for my $key ( @CLAMD_MANAGED_KEYS ) {
        # First active setting (same as the clamav-daemon config script)
        my ( $value ) = $content =~ /^\Q$key\E[\t ]+(\S+)/m or next;
        next unless $value =~ /^[A-Za-z0-9_-]+\z/;
        $selections .= "clamav-daemon clamav-daemon/$key string $value\n";
    }
    return unless length $selections;

    my $tmp = File::Temp->new( TEMPLATE => 'imscp-clamav-debconf.XXXXXXXX', TMPDIR => 1 );
    print { $tmp } $selections or die( sprintf( "Couldn't write %s: %s", $tmp->filename(), $! ));
    $tmp->flush() or die( sprintf( "Couldn't write %s: %s", $tmp->filename(), $! ));

    my $rs = execute( [ $cmd, $tmp->filename() ], \my $stdout, \my $stderr );
    debug( $stdout ) if length $stdout;
    $rs == 0 or die( sprintf(
        "Couldn't update the clamav-daemon debconf answers: %s", $stderr || $stdout || 'Unknown error'
    ));
}

=item _hasClamdSocketUnit( )

 Is the clamd socket managed by systemd (clamav-daemon.socket unit)?

 Return bool

=cut

sub _systemctlSocket
{
    my ( $action ) = @_;
    my $rs = execute( [ 'systemctl', '--quiet', $action, 'clamav-daemon.socket' ], \my $stdout, \my $stderr );
    debug( $stdout ) if length $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $rs;
}

sub _hasClamdSocketUnit
{
    my $serviceMngr = iMSCP::Service->getInstance();
    return 0 unless $serviceMngr->isSystemd();

    # iMSCP::Service::hasService() only recognizes '.service' units, so the
    # '.socket' unit must be looked up directly.
    ( grep { -f "$_/clamav-daemon.socket" } qw(
        /etc/systemd/system /run/systemd/system /usr/lib/systemd/system
        /lib/systemd/system
    ) ) ? 1 : 0;
}

=item _getSystemdDropIns( )

 Get the systemd drop-in files to install

 Return hash Drop-in file content indexed by unit name

=cut

sub _getSystemdDropIns
{
    my ( $self ) = @_;

    my $header = <<'EOT';
# Auto-generated by the i-MSCP ClamAV plugin
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
EOT

    my %dropIns = (
        'clamav-daemon.service' => <<"EOT",
$header
[Service]
Restart=on-failure
RestartSec=10s
EOT
    );

    if ( _hasClamdSocketUnit() ) {
        my $options = $self->{'config'}->{'clamd_options'};
        $options->{'LocalSocketGroup'} =~ /^[a-z_][a-z0-9_-]*\z/ && $options->{'LocalSocketMode'} =~ /^[0-7]{3}\z/ or die(
            'Invalid clamd socket options'
        );
        $dropIns{'clamav-daemon.socket'} = <<"EOT";
$header#
# The clamd socket is created by systemd (socket activation): clamd(8) then
# ignores the clamd.conf(5) LocalSocketGroup and LocalSocketMode settings.
[Socket]
SocketGroup=$options->{'LocalSocketGroup'}
SocketMode=0$options->{'LocalSocketMode'}
EOT
    }

    my $milter = "$header\n[Service]\nRestart=on-failure\nRestartSec=10s\n";
    unless ( grep { -f "$_/clamav-milter.service" } $SYSTEMD_UNIT_DIR, '/usr/lib/systemd/system', '/lib/systemd/system' ) {
        # Unit generated from the SysV init script (RemainAfterExit=yes, no
        # main PID). systemd needs to know the main PID to restart the service.
        my $options = $self->{'config'}->{'clamav_milter_options'};
        my $pidFile = ( $options->{'Foreground'} // '' ) =~ /^(?:yes|true|1)\z/i
            ? '/run/clamav/daemon-clamav-milter.pid' : $options->{'PidFile'} // '';
        $pidFile =~ s%^/var/run/%/run/%;
        if ( $pidFile =~ m%^/run/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\z% && $pidFile !~ m%/\.\.?(?:/|\z)% ) {
            $milter .= "RemainAfterExit=no\nPIDFile=$pidFile\n";
        } else {
            debug( "clamav-milter PidFile isn't set or is located outside of /run. Skipping systemd Restart setting." );
            undef $milter;
        }
    }
    $dropIns{'clamav-milter.service'} = $milter if defined $milter;

    %dropIns;
}

=item _configureClamdSystemd( [ $action = 'deconfigure' ] )

 Install or remove the systemd drop-in files

 Param string $action Action to be performed (configure|deconfigure)
 Return void, die on failure

=cut

sub _configureClamdSystemd
{
    my ( $self, $action ) = @_;

    my $serviceMngr = iMSCP::Service->getInstance();
    return unless $serviceMngr->isSystemd();

    my %dropIns = $action eq 'configure' ? $self->_getSystemdDropIns() : ();
    my $reload = 0;
    for my $unit ( qw/ clamav-daemon.service clamav-daemon.socket clamav-milter.service / ) {
        my $dir = "$SYSTEMD_UNIT_DIR/$unit.d";
        my $file = "$dir/$SYSTEMD_DROPIN_FILENAME";

        if ( defined $dropIns{$unit} ) {
            _secureDir( $dir, 0, 0, 0755 );
            _writeFileAtomic( $file, $dropIns{$unit}, 0, 0, 0644 );
            $reload = 1;
            next;
        }

        next unless lstat $file;
        unlink( $file ) or die( sprintf( "Couldn't remove %s: %s", $file, $! ));
        # Only if empty (distribution drop-in files are kept)
        rmdir( $dir ) if -d $dir && !-l $dir;
        $reload = 1;
    }

    $serviceMngr->getProvider()->daemonReload() if $reload;
}

=item _getPostfixMilterValue( $config )

 Get Postfix milter value (with per-milter default action) for the given configuration

 Param hashref $config Plugin configuration
 Return string

=cut

sub _getPostfixMilterValue
{
    my ( undef, $config ) = @_;

    my $defaultAction = $config->{'PostfixMilterDefaultAction'} // 'tempfail';
    "{ $config->{'PostfixMilterSocket'}, default_action=$defaultAction }";
}

=item _configurePostfix( [ $action = 'deconfigure' ] )

 Configure or deconfigure postfix

 Only the milter entries that belong to this plugin are added/removed. Entries
 added by other plugins, such as the OpenDKIM or SpamAssassin plugins, are left
 untouched.

 Param string $action Action to be performed (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configurePostfix
{
    my ( $self, $action ) = @_;
    $action //= 'deconfigure';

    my $mta = Servers::mta->factory();

    # Remove previous and current milter entries, in both legacy (plain) and
    # new (per-milter settings) forms
    my @milterRegexps = map {
        qr/^(?:\{\s*)?\Q$_\E(?:\s*,.*\})?$/
    } grep { defined && length } (
        $self->{'config_prev'}->{'PostfixMilterSocket'},
        $self->{'config'}->{'PostfixMilterSocket'}
    );

    my $rs = $mta->postconf( (
        smtpd_milters     => {
            action => 'remove',
            values => [ @milterRegexps ]
        },
        non_smtpd_milters => {
            action => 'remove',
            values => [ @milterRegexps ]
        }
    ));
    return $rs if $rs || $action ne 'configure';

    my $milterValue = $self->_getPostfixMilterValue( $self->{'config'} );
    $mta->postconf( (
        smtpd_milters     => {
            action => 'add',
            values => [ $milterValue ]
        },
        non_smtpd_milters => {
            action => 'add',
            values => [ $milterValue ]
        }
    ));
}

=item _installDistributionPackages( )

 Install required distribution packages

 Return int 0 on success, other on failure

=cut

sub _installDistributionPackages
{
    my ( $self ) = @_;

    local $ENV{'DEBIAN_FRONTEND'} = 'noninteractive';
    # The clamav-milter.conf and clamd.conf files are managed through UCF(1).
    # Make sure that our changes are kept on package upgrades
    local $ENV{'UCF_FORCE_CONFFOLD'} = 1;

    my $rs = execute( [ 'apt-get', 'update' ], \my $stdout, \my $stderr );
    debug( $stdout ) if $stdout;
    error( sprintf( "Couldn't update APT index: %s", $stderr || 'Unknown error' )) if $rs;
    return $rs if $rs;

    # First installation: preseed the clamav-daemon debconf answers so that
    # the clamd socket is never world-accessible (Debian default: 666). The
    # clamd.conf file, when it exists, is authoritative (the clamav-daemon
    # config script reads it) and is updated on plugin activation.
    unless ( -e $CLAMD_CONF ) {
        local $@;
        eval {
            my $options = $self->{'config'}->{'clamd_options'};
            $self->_syncClamdDebconf( join '', map { "$_ $options->{$_}\n" } @CLAMD_MANAGED_KEYS );
        };
        if ( $@ ) {
            error( $@ );
            return 1;
        }
    }

    $rs = execute(
        [
            'apt-get', '-o', 'DPkg::Options::=--force-confold', '-o', 'DPkg::Options::=--force-confdef',
            '-o', 'DPkg::Options::=--force-confmiss', '--assume-yes', '--no-install-recommends',
            '--quiet', 'install', 'clamav', 'clamav-base', 'clamav-daemon', 'clamav-freshclam',
            'clamav-milter', 'clamdscan', 'curl', 'gnupg', 'rsync', 'bind9-dnsutils'
        ],
        \$stdout,
        \$stderr
    );
    debug( $stdout ) if $stdout;
    error( sprintf( "Couldn't install distribution packages: %s", $stderr || 'Unknown error' )) if $rs;
    $rs;
}

=item _initClamAVdatabases

 Initialize ClamAV databases

 Return int 0 on success, other on failure

=cut

sub _initClamAVdatabases
{
    local $@;
    eval { iMSCP::Service->getInstance()->stop( 'clamav-freshclam' ); };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    # FRESHCLAM(1) exit codes: 0 = database successfully updated,
    # 1 = database already up-to-date
    my $rs = execute( [ 'freshclam', '--stdout' ], \my $stdout, \my $stderr );
    debug( $stdout ) if $stdout;

    if ( $rs > 1 ) {
        # Do not fail if databases are already available (e.g. on rate-limit
        # (HTTP 429) or temporary network failure, freshclam fails while clamd
        # would still be operational)
        if ( ( grep { -f "/var/lib/clamav/main.$_" } qw/ cvd cld / )
            && ( grep { -f "/var/lib/clamav/daily.$_" } qw/ cvd cld / )
        ) {
            debug( sprintf( "Couldn't update ClamAV databases: %s", $stderr || $stdout || 'Unknown error' ));
            return 0;
        }

        error( sprintf( "Couldn't initialize ClamAV databases: %s", $stderr || $stdout || 'Unknown error' ));
        return $rs;
    }

    0;
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
