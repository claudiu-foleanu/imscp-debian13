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
use File::Spec;
use parent 'Common::SingletonClass';

# clamav-unofficial-sigs script location. Older plugin versions installed it
# into /usr/local/bin.
my $CUS_SCRIPT = '/usr/local/sbin/clamav-unofficial-sigs.sh';
my $CUS_SCRIPT_OLD = '/usr/local/bin/clamav-unofficial-sigs.sh';
my $CUS_CONF_DIR = '/etc/clamav-unofficial-sigs';
my $CUS_WORK_DIR = '/var/lib/clamav-unofficial-sigs';
my $CUS_LOG_DIR = '/var/log/clamav-unofficial-sigs';
our $CLAMAV_MILTER_CONF = '/etc/clamav/clamav-milter.conf';

=head1 DESCRIPTION

 i-MSCP ClamAV plugin backend.

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

    my $rs = $self->_configureClamavMilter( 'configure' );
    $rs ||= $self->_configurePostfix( 'configure' );
    return $rs if $rs;

    my $serviceTasksSub = sub {
        local $@;
        eval {
            my $serviceMngr = iMSCP::Service->getInstance();
            for my $service ( qw/ clamav-freshclam clamav-daemon / ) {
                $serviceMngr->enable( $service );
                $serviceMngr->restart( $service );
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

        # Generate the cron, logrotate and man files
        $rs = execute( [ $CUS_SCRIPT, '--install-all' ], \my $stdout, \my $stderr );
        debug( $stdout ) if length $stdout;
        error( sprintf(
            "Couldn't install clamav-unofficial-sigs cron, logrotate and man files: %s",
            $stderr || $stdout || 'Unknown error'
        )) if $rs;
        return $rs if $rs;

        # First signatures update (silent mode)
        $rs = execute( [ $CUS_SCRIPT, '--silence' ], \$stdout, \$stderr );
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

    my @files = (
        '/etc/cron.d/clamav-unofficial-sigs',
        '/etc/logrotate.d/clamav-unofficial-sigs',
        '/usr/share/man/man8/clamav-unofficial-sigs.8'
    );

    # The purge.txt file lists the third-party databases installed by the
    # script. Because the file is written by the clamav user (cron task), only
    # paths that belong to the ClamAV databases or script directories are
    # honored.
    my $purgeFile = "$CUS_WORK_DIR/configs/purge.txt";
    if ( -f $purgeFile && !-l $purgeFile ) {
        my $fileContent = iMSCP::File->new( filename => $purgeFile )->get();
        unless ( defined $fileContent ) {
            error( sprintf( "Couldn't read the %s file", $purgeFile ));
            return 1;
        }

        for my $path ( split /\n/, $fileContent ) {
            $path =~ s/^\s+|\s+$//g;
            next unless length $path
                && $path !~ m%(?:^|/)\.\.(?:/|$)%
                && $path =~ m%^(?:/var/lib/clamav|\Q$CUS_WORK_DIR\E|\Q$CUS_LOG_DIR\E|\Q$CUS_CONF_DIR\E)/[^\0]+$%;
            push @files, File::Spec->canonpath( $path );
        }
    }

    for my $file ( @files ) {
        next unless -f $file || -l $file;
        my $rs = iMSCP::File->new( filename => $file )->delFile();
        return $rs if $rs;
    }

    local $@;
    eval {
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
        iMSCP::Dir->new( dirname => $socketDir )->make( {
            user  => $options->{'User'} || 'clamav',
            group => $options->{'MilterSocketGroup'} || 'clamav',
            mode  => 0755
        } );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
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
    local $ENV{'DEBIAN_FRONTEND'} = 'noninteractive';
    # The clamav-milter.conf file is managed through UCF(1). Make sure that our
    # changes are kept on package upgrades
    local $ENV{'UCF_FORCE_CONFFOLD'} = 1;

    my $rs = execute( [ 'apt-get', 'update' ], \my $stdout, \my $stderr );
    debug( $stdout ) if $stdout;
    error( sprintf( "Couldn't update APT index: %s", $stderr || 'Unknown error' )) if $rs;
    return $rs if $rs;

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

=head1 AUTHORS

 Laurent Declercq <l.declercq@nuxwin.com>
 Rene Schuster <mail@reneschuster.de>
 Sascha Bay <info@space2place.de>

=cut

1;
__END__
