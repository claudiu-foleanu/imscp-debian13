=head1 NAME

 Plugin::SpamAssassin

=cut

# i-MSCP SpamAssassin plugin
# Copyright (C) 2015-2017 Laurent Declercq <l.declercq@nuxwin.com>
# Copyright (C) 2013-2016 Sascha Bay <info@space2place.de>
# Copyright (C) 2013-2016 Rene Schuster <mail@reneschuster.de>
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

package Plugin::SpamAssassin;

use strict;
use warnings;
use iMSCP::Crypt qw/ ALNUM randomStr /;
use autouse 'iMSCP::Debug' => qw/ debug error /;
use autouse 'iMSCP::Execute' => qw/ execute /;
use autouse 'iMSCP::Rights' => qw/ setRights /;
use autouse 'iMSCP::TemplateParser' => qw/ process replaceBloc /;
use Class::Autouse qw/ :nostat
    iMSCP::Database iMSCP::Dir iMSCP::File iMSCP::Service iMSCP::SystemUser Servers::cron Servers::mta Servers::sqld /;
use Cwd qw/ realpath /;
use Fcntl qw/ O_RDONLY O_NOFOLLOW O_NONBLOCK O_DIRECTORY S_ISDIR S_ISREG S_ISVTX S_IWGRP S_IWOTH /;
use File::Basename qw/ dirname /;
use iMSCP::Umask;
use POSIX ();
use List::MoreUtils qw/ uniq /;
use Module::Load::Conditional qw/ check_install /;
use version;
use parent 'Common::SingletonClass';

# Roundcube plugins provided by this plugin (third-party plugins, shipped in
# the roundcube-plugins directory)
my @RC_PLUGINS_3RD_PARTY = qw/ sauserprefs /;

=head1 DESCRIPTION

 This package provides the backend part for the i-MSCP SpamAssassin plugin.

 Security notes:
  - The SPAMD(8p) home directory (/var/lib/spamassassin) is owned by the
    SPAMD(8p) user. Its subdirectories are created/updated as that user
    (RUNUSER(1)); root never changes ownership/permissions through a path
    controlled by that user.
  - The sa-learn spool directories are owned by the panel user (written by
    the markasjunk Roundcube plugin). They are created as the panel user. The
    learning task (run as root by cron) pins each directory (chdir + inode
    check), opens messages with O_NOFOLLOW, feeds them to SA-LEARN(1p) through
    its standard input and runs SA-LEARN(1p) as the SPAMD(8p) user.
  - The cron tasks run plugin scripts that load this (panel user owned)
    backend as root. This is by design in i-MSCP (all plugin backends run as
    root); the panel user is therefore root-equivalent.

=head1 PUBLIC METHODS

=over 4

=item update( $fromVersion )

 Perform update tasks

 Param $string $fromVersion Version from which plugin is being updated
 Return int 0 on success, other on failure

=cut

sub update
{
    my ( $self, $fromVersion ) = @_;

    $fromVersion = version->parse( $fromVersion );

    if ( $fromVersion < version->parse( '2.0.0' ) && -f '/etc/spamassassin/00_imscp.pre' ) {
        my $rs = iMSCP::File->new( filename => '/etc/spamassassin/00_imscp.pre' )->delFile();
        return $rs if $rs;
    }

    return 0 unless $fromVersion < version->parse( '2.1.0' );

    # The DecodeShortURLs SpamAssassin plugin is provided by SpamAssassin
    # itself since version 4.0. Remove the 3rd-party version files.
    for my $file ( '/etc/spamassassin/DecodeShortURLs.cf', '/etc/spamassassin/DecodeShortURLs.pm' ) {
        next unless -f $file;
        my $rs = iMSCP::File->new( filename => $file )->delFile();
        return $rs if $rs;
    }

    # The markasjunk2 Roundcube plugin has been superseded by the markasjunk
    # Roundcube core plugin
    local $@;
    eval {
        for my $dir (
            "$::imscpConfig{'GUI_PUBLIC_DIR'}/tools/webmail/plugins/markasjunk2",
            "$self->{'_rc_dir'}/plugins/markasjunk2"
        ) {
            iMSCP::Dir->new( dirname => $dir )->remove();
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
    my ( $self ) = @_;

    unless ( defined $::execmode && $::execmode eq 'setup'
        || !grep ( $_ eq $self->{'action'}, 'install', 'update' )
    ) {
        my $rs = $self->_installDistributionPackages();
        return $rs if $rs;
    }

    my $rs = $self->_createSpamdUser();
    $rs ||= $self->_createSaSqlUser();
    $rs ||= $self->_configureSa( 'configure' );
    $rs ||= $self->_installSaPlugins( 'install' );
    $rs ||= $self->_setupSaPlugins();
    $rs ||= $self->_configureHeinleinRuleset( 'configure' );
    $rs ||= $self->_configureSpamassMilter( 'configure' );
    $rs ||= $self->_configurePostfix( 'configure' );
    return $rs if $rs;

    my $serviceTasksSub = sub {
        local $@;
        eval {
            my $serviceMngr = iMSCP::Service->getInstance();
            for my $service ( $self->{'_spamd_service'}, 'spamass-milter' ) {
                $serviceMngr->enable( $service );
                $serviceMngr->restart( $service );
            }
        };
        if ( $@ ) {
            error( $@ );
            return 1;
        }

        $self->_configureSaMaintenance( 'configure' );
    };

    if ( defined $::execmode && $::execmode eq 'setup' ) {
        $rs = $self->{'eventManager'}->register(
            'beforeSetupRestartServices',
            sub {
                unshift @{ $_[0] }, [ $serviceTasksSub, 'SpamAssassin' ];
                0;
            }
        );
        return $rs if $rs;
    } else {
        $rs = $serviceTasksSub->();
        return $rs if $rs;
        undef $serviceTasksSub;
    }

    return 0 unless $self->_isRoundcubeAvailable();

    $rs = $self->_installRoundcubePlugins( 'install' );
    $rs ||= $self->_configureRoundcubePlugins( 'configure' );
    $rs ||= $self->_enableRoundcubePlugins( 'enable' );
    return $rs if $rs || defined $::execmode && $::execmode eq 'setup';

    $self->_reloadPanel();
}

=item disable( )

 Perform disable tasks

 Return int 0 on success, other on failure

=cut

sub disable
{
    my ( $self ) = @_;

    for my $cronjob ( qw/ BayesSaLearn CleanAwlDb CleanBayesDb DiscoverRazor / ) {
        my $rs = $self->_unregisterCronjob( $cronjob );
        return $rs if $rs;
    }

    if ( $self->_isRoundcubeAvailable() ) {
        my $rs = $self->_enableRoundcubePlugins( 'disable' );
        $rs ||= $self->_configureRoundcubePlugins( 'deconfigure' );
        $rs ||= $self->_installRoundcubePlugins( 'uninstall' );
        return $rs if $rs;

        unless ( defined $::execmode && $::execmode eq 'setup' ) {
            $rs = $self->_reloadPanel();
            return $rs if $rs;
        }
    }

    my $rs = $self->_configurePostfix( 'deconfigure' );
    $rs ||= $self->_configureSpamassMilter( 'deconfigure' );
    $rs ||= $self->_configureHeinleinRuleset( 'deconfigure' );
    $rs ||= $self->_installSaPlugins( 'uninstall' );
    $rs ||= $self->_configureSa( 'deconfigure' );
    return $rs if $rs;

    local $@;
    eval { Servers::sqld->factory()->dropUser( 'sa_user', $::imscpConfig{'DATABASE_USER_HOST'} ); };
    if ( $@ ) {
        error( sprintf( "Couldn't drop SpamAssassin SQL user: %s", $@ ));
        return 1;
    }

    return 0 if $self->{'action'} ne 'disable';

    # The SPAMASS_MILTER(8) service is about to be stopped. Make Postfix aware
    # of the change immediately.
    unless ( defined $::execmode && $::execmode eq 'setup' ) {
        $rs = Servers::mta->factory()->reload();
        return $rs if $rs;
    }

    $rs = $self->_configureSaMaintenance( 'deconfigure' );
    return $rs if $rs;

    eval {
        my $serviceMngr = iMSCP::Service->getInstance();
        for my $service ( 'spamass-milter', $self->{'_spamd_service'} ) {
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

=item discoverRazor( )

 Create the Razor server list files

 Return int 0 on success, other on failure

=cut

sub discoverRazor
{
    my ( $self ) = @_;

    my $rs = execute(
        [
            'runuser', '-u', $self->{'config'}->{'spamd'}->{'user'}, '--',
            'razor-admin', "-home=$self->{'config'}->{'spamd'}->{'homedir'}/.razor", '-discover'
        ],
        \my $stdout,
        \my $stderr
    );
    debug( $stdout ) if $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $rs;
}

=item cleanAwlDb( )

 Clean the SpamAssassin (AWL) database

 Return int 0 on success, other on failure

=cut

sub cleanAwlDb
{
    my $dbh = iMSCP::Database->factory();
    my $dbi = $dbh->getRawDb();
    my $oldDb;

    local $@;
    eval {
        local $dbi->{'RaiseError'} = 1;
        $oldDb = $dbh->useDatabase( "$::imscpConfig{'DATABASE_NAME'}_spamassassin" );
        $dbi->do(
            '
                DELETE FROM awl
                WHERE (msgcount = 1 AND last_hit < DATE_SUB(NOW(), INTERVAL 1 WEEK))
                OR (last_hit < DATE_SUB(NOW(), INTERVAL 1 MONTH))
            '
        );
        $dbh->useDatabase( $oldDb ) if $oldDb;
    };
    if ( $@ ) {
        $dbh->useDatabase( $oldDb ) if $oldDb;
        error( $@ );
        return 1;
    }

    0;
}

=item cleanBayesDb( )

 Expire old tokens from the bayes database

 Return int 0 on success, other on failure

=cut

sub cleanBayesDb
{
    my ( $self ) = @_;

    # The Bayes database is stored in SQL. No need for root privileges.
    my $rs = execute( [ $self->_spamdUserCmd( 'sa-learn', '--force-expire' ) ], \my $stdout, \my $stderr );
    debug( $stdout ) if $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $rs;
}

=item bayesSaLearn( )

 Train SpamAssassin's Bayesian classifier with spam and ham reported by the users

 Messages are stored by the markasjunk Roundcube plugin (dir_learn driver) in
 the sa-learn/spam and sa-learn/ham directories, using the '<username>__XXXXXX'
 filename pattern. Messages are deleted once learned.

 Return int 0 on success, other on failure

=cut

sub bayesSaLearn
{
    my ( $self ) = @_;

    my $saLearnDir = $self->{'_sa_learn_dir'};
    my $panelUid = getpwnam( $self->{'_panel_user'} );
    defined $panelUid or do {
        error( "Couldn't find the panel unix user" );
        return 1;
    };

    my $learned = 0;
    my $rs = 0;

    local $@;
    eval {
        # New layout (markasjunk): <saLearnDir>/<spam|ham>/<username>__XXXXXX
        # Legacy layout (markasjunk2): <saLearnDir>/<username>__<spam|ham>__XXXXXX
        for my $spec (
            [ $saLearnDir, undef ],
            [ "$saLearnDir/spam", 'spam' ],
            [ "$saLearnDir/ham", 'ham' ]
        ) {
            my ( $dir, $dirMode ) = @{ $spec };

            # The directories are writable by the panel user. Pin the
            # directory (chdir + inode check) so that it can't be swapped with
            # a symlink while being processed. All operations below use
            # relative filenames.
            next unless _pinDirectory( $dir, $panelUid );

            opendir( my $dh, '.' ) or die( sprintf( "Couldn't open the %s directory: %s", $dir, $! ));
            my @entries = grep { !/^\.{1,2}\z/s } readdir( $dh );
            closedir( $dh );

            for my $entry ( @entries ) {
                my ( $username, $mode );
                if ( defined $dirMode ) {
                    ( $username ) = $entry =~ /^(.+)__[A-Za-z0-9]{6}$/;
                    $mode = $dirMode;
                } else {
                    # Only legacy files in the base directory (never touch
                    # .gitkeep, .gitignore, spam/ or ham/)
                    ( $username, $mode ) = $entry =~ /^(.+)__(spam|ham)__[A-Za-z0-9]{6}$/ or next;
                }

                lstat $entry or next;
                if ( -l _ ) {
                    # Never follow symlinks; just remove them
                    unlink( $entry );
                    next;
                }
                next unless -f _;

                sysopen( my $fh, $entry, O_RDONLY | O_NOFOLLOW | O_NONBLOCK ) or do {
                    debug( sprintf( "Couldn't open the %s/%s file: %s", $dir, $entry, $! ));
                    next;
                };
                my @st = stat $fh;

                # Only learn regular files owned by the panel user, with a single
                # link (no hard link to a file we shouldn't read)
                if ( S_ISREG( $st[2] ) && $st[4] == $panelUid && $st[3] == 1
                    && defined $username && $username =~ /^[^\s\/\@-][^\s\/\@]*\@[^\s\/\@]+$/
                ) {
                    my ( $ret, $output ) = $self->_saLearnFromFh( $fh, $mode, $username );
                    debug( $output ) if length $output;
                    if ( $ret ) {
                        # Keep the file. It will be processed again on next run.
                        error( sprintf( "Couldn't learn the %s/%s message: %s", $dir, $entry, $output || 'Unknown error' ));
                        $rs = $ret;
                        return;
                    }
                    $learned++;
                } else {
                    debug( sprintf( 'Skipping %s/%s file: unexpected filename, owner or type', $dir, $entry ));
                }
                close( $fh );

                # Messages contain private user data. Remove them once processed.
                unlink( $entry ) or die( sprintf( "Couldn't remove the %s/%s file: %s", $dir, $entry, $! ));
            }
        }
    };
    my $err = $@;
    chdir( '/' );
    if ( $err ) {
        error( $err );
        return 1;
    }

    return $rs if $rs || !$learned;

    # Synchronize the database and the journal once per training session
    $rs = execute( [ $self->_spamdUserCmd( 'sa-learn', '--sync' ) ], \my $stdout, \my $stderr );
    debug( $stdout ) if $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $rs;
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 Initialize plugin

 Return Plugin::SpamAssassin, die on failure

=cut

sub _init
{
    my ( $self ) = @_;

    $self->{'FORCE_RETVAL'} = 'yes';
    $self->{'_panel_user'} = $::imscpConfig{'SYSTEM_USER_PREFIX'} . $::imscpConfig{'SYSTEM_USER_MIN_UID'};
    $self->{'_panel_group'} = getgrgid( ( getpwnam( $self->{'_panel_user'} ) )[3] ) or die(
        "Couldn't find panel unix user group"
    );

    for my $param ( qw/ spamd spamass_milter spamassassin roundcube / ) {
        ref $self->{'config'}->{$param} eq 'HASH' or die( sprintf(
            'Missing or invalid %s configuration parameter', $param
        ));
    }

    # SPAMD(8p) user/group (configurable since v2.0.2)
    $self->{'config'}->{'spamd'}->{'user'} //= 'debian-spamd';
    $self->{'config'}->{'spamd'}->{'group'} //= $self->{'config'}->{'spamd'}->{'user'};
    $self->{'config'}->{'spamd'}->{'homedir'} //= '/var/lib/spamassassin';

    for my $param ( qw/ user group / ) {
        $self->{'config'}->{'spamd'}->{$param} =~ /^[a-z_][a-z0-9_-]*\$?$/ or die( sprintf(
            "Invalid value for the spamd '%s' configuration parameter", $param
        ));
    }
    $self->{'config'}->{'spamd'}->{'homedir'} =~ m%^/[A-Za-z0-9._/-]+$% or die(
        "Invalid value for the spamd 'homedir' configuration parameter"
    );

    $self->{'config'}->{'spamd'}->{'options'} = process(
        {
            SPAMD_USER    => $self->{'config'}->{'spamd'}->{'user'},
            SPAMD_GROUP   => $self->{'config'}->{'spamd'}->{'group'},
            SPAMD_HOMEDIR => $self->{'config'}->{'spamd'}->{'homedir'}
        },
        $self->{'config'}->{'spamd'}->{'options'} // ''
    );

    # Values that end in shell sourced files (/etc/default/*)
    for my $value (
        $self->{'config'}->{'spamd'}->{'options'},
        @{ $self->{'config'}->{'spamass_milter'} }{qw/ options socket_path socket_owner socket_mode /},
        @{ $self->{'config'}->{'spamass_milter'}->{'networks'} // [] }
    ) {
        defined $value && $value !~ /["`\$\\\r\n]/ or die(
            "Invalid characters found in the spamd or spamass_milter configuration parameters"
        );
    }

    $self->{'config'}->{'spamass_milter'}->{'spam_reject_policy'} =~ /^-?\d+$/ or die(
        "Invalid value for the spamass_milter 'spam_reject_policy' configuration parameter"
    );
    $self->{'config'}->{'spamass_milter'}->{'postfix_milter_default_action'} //= 'tempfail';
    $self->{'config'}->{'spamass_milter'}->{'postfix_milter_default_action'} =~ /^(?:accept|reject|tempfail|quarantine)$/ or die(
        "Invalid value for the spamass_milter 'postfix_milter_default_action' configuration parameter"
    );

    # Roundcube markasjunk2 plugin has been superseded by the markasjunk core plugin
    $self->{'config'}->{'roundcube'}->{'markasjunk'} //= delete $self->{'config'}->{'roundcube'}->{'markasjunk2'} // {
        enabled => 0
    };
    $self->{'config'}->{'roundcube'}->{'sauserprefs'} //= { enabled => 0 };

    # The spamd package/service (Debian >= 12) replaces the spamassassin service
    $self->{'_spamd_service'} = -f '/etc/default/spamd' || !-f '/etc/default/spamassassin' ? 'spamd' : 'spamassassin';

    $self->{'_rc_dir'} = "$::imscpConfig{'GUI_ROOT_DIR'}/vendor/imscp/roundcube/roundcubemail";
    $self->{'_sa_learn_dir'} = "$::imscpConfig{'PLUGINS_DIR'}/SpamAssassin/sa-learn";
    $self;
}

=item _spamdUserCmd( @command )

 Return the given command, wrapped to be run as the SPAMD(8p) user with a
 clean environment

 Param list @command Command and its arguments
 Return list

=cut

sub _spamdUserCmd
{
    my ( $self, @command ) = @_;

    (
        'runuser', '-u', $self->{'config'}->{'spamd'}->{'user'}, '--',
        'env', '-i', "HOME=$self->{'config'}->{'spamd'}->{'homedir'}", 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LANG=C',
        @command
    );
}

=item _saLearnFromFh( $fh, $mode, $username )

 Learn the message read from the given file handle (fed to SA-LEARN(1p) on
 its standard input), as the SPAMD(8p) user

 Param filehandle $fh Message file handle
 Param string $mode Learning mode (spam|ham)
 Param string $username SpamAssassin username
 Return list (exit status, output)

=cut

sub _saLearnFromFh
{
    my ( $self, $fh, $mode, $username ) = @_;

    my @command = $self->_spamdUserCmd( 'sa-learn', '--no-sync', "--$mode", '-u', $username );

    sysseek( $fh, 0, 0 );
    my $pid = open( my $out, '-|' );
    defined $pid or return ( 1, "Couldn't fork: $!" );

    unless ( $pid ) {
        # Child
        open( STDIN, '<&', $fh ) or POSIX::_exit( 127 );
        open( STDERR, '>&', \*STDOUT ) or POSIX::_exit( 127 );
        chdir( '/' );
        exec { $command[0] } @command or POSIX::_exit( 127 );
    }

    my $output = do { local $/; <$out> } // '';
    close( $out );
    ( $? == 0 ? 0 : ( $? >> 8 ) || 1, $output );
}

=item _runAsUser( $user, @command )

 Run the given command as the given user (RUNUSER(1))

 Used to create/update files inside directories owned by unprivileged users,
 so that symlinks planted by those users can't be abused.

 Param string $user Username
 Param list @command Command and its arguments
 Return void, die on failure

=cut

sub _runAsUser
{
    my ( undef, $user, @command ) = @_;

    my $rs = execute(
        [ 'runuser', '-u', $user, '--', 'env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LANG=C', @command ],
        \my $stdout,
        \my $stderr
    );
    debug( $stdout ) if $stdout;
    $rs == 0 or die( sprintf( "Couldn't run '%s' as %s: %s", "@command", $user, $stderr || 'Unknown error' ));
}

=item _installDistributionPackages( )

 Install required distribution packages

 Return int 0 on success, other on failure

=cut

sub _installDistributionPackages
{
    local $ENV{'DEBIAN_FRONTEND'} = 'noninteractive';
    local $ENV{'UCF_FORCE_CONFFOLD'} = 1;

    my $rs = execute( [ 'apt-get', 'update' ], \my $stdout, \my $stderr );
    debug( $stdout ) if $stdout;
    error( sprintf( "Couldn't update APT index: %s", $stderr || 'Unknown error' )) if $rs;
    return $rs if $rs;

    $rs = execute(
        [
            'apt-get', '-o', 'DPkg::Options::=--force-confold', '-o', 'DPkg::Options::=--force-confdef',
            '-o', 'DPkg::Options::=--force-confmiss', '--assume-yes', '--no-install-recommends',
            '--quiet', 'install', 'spamassassin', 'spamd', 'spamc', 'sa-compile', 'spamass-milter', 'gnupg',
            'libdbd-mariadb-perl', 'libnet-ident-perl', 'libmail-dkim-perl', 'libmail-spf-perl',
            'libencode-detect-perl', 'libnet-patricia-perl', 'libmail-dmarc-perl', 'pyzor', 'razor'
        ],
        \$stdout,
        \$stderr
    );
    debug( $stdout ) if $stdout;
    error( sprintf( "Couldn't install distribution packages: %s", $stderr || 'Unknown error' )) if $rs;
    $rs;
}

=item _createSpamdUser( )

 Create SPAMD(8p) unix user if needed and setup its home directory

 Return int 0 on success, other on failure

=cut

sub _createSpamdUser
{
    my ( $self ) = @_;

    my ( $user, $group, $homedir ) = @{ $self->{'config'}->{'spamd'} }{qw/ user group homedir /};

    # On Debian, the debian-spamd user is created by the spamassassin package.
    # We do not want alter it (e.g. its login shell), hence we create the user
    # only if it doesn't exist yet. Commands are run through RUNUSER(1) which
    # doesn't depend on the login shell.
    unless ( getpwnam( $user ) ) {
        my $rs = iMSCP::SystemUser->new( {
            username       => $user,
            group          => getgrnam( $group ) ? $group : undef,
            system         => 1,
            comment        => 'SpamAssassin daemon',
            home           => $homedir,
            skipCreateHome => 1,
            shell          => '/usr/sbin/nologin'
        } )->addSystemUser();
        return $rs if $rs;
    }

    local $@;
    eval {
        # The home directory itself lives in a root-owned directory: create it
        # (or fix it) as root, refusing symlinks
        _secureDir( $homedir, $user, $group, 0755 );

        # Subdirectories are created as the SPAMD(8p) user, as it owns the
        # home directory (never chown/chmod as root through a path controlled
        # by that user)
        $self->_runAsUser( $user, 'mkdir', '-p', '-m', '0700', '--', "$homedir/sa-update-keys" );
        $self->_runAsUser( $user, 'chmod', '0700', '--', "$homedir/sa-update-keys" );

        # Import the SpamAssassin rules signing key (already done by the
        # spamassassin package postinst script for the debian-spamd user)
        unless ( -s "$homedir/sa-update-keys/pubring.gpg" || -s "$homedir/sa-update-keys/pubring.kbx" ) {
            my ( $stdout, $stderr );
            execute(
                [
                    'runuser', '-u', $user, '--', 'sa-update', '--gpghomedir', "$homedir/sa-update-keys",
                    '--import', '/usr/share/spamassassin/GPG.KEY'
                ],
                \$stdout,
                \$stderr
            ) == 0 or die( $stderr || 'Unknown error' );
            debug( $stdout ) if $stdout;
        }
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _setupPyzor( )

 Setup Pyzor

 Pyzor >= 1.0 doesn't provide the `discover' command anymore. The public
 Pyzor server is used by default. We only make sure that the Pyzor home
 directory exists.

 Return int 0 on success, other on failure

=cut

sub _setupPyzor
{
    my ( $self ) = @_;

    local $@;
    eval {
        # Created as the SPAMD(8p) user (owner of the home directory)
        my $dir = "$self->{'config'}->{'spamd'}->{'homedir'}/.pyzor";
        $self->_runAsUser( $self->{'config'}->{'spamd'}->{'user'}, 'mkdir', '-p', '-m', '0700', '--', $dir );
        $self->_runAsUser( $self->{'config'}->{'spamd'}->{'user'}, 'chmod', '0700', '--', $dir );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _setupRazor( )

 Setup Razor

 Return int 0 on success, other on failure

=cut

sub _setupRazor
{
    my ( $self ) = @_;

    my $razorHome = "$self->{'config'}->{'spamd'}->{'homedir'}/.razor";
    return 0 if -f "$razorHome/identity";

    for my $action ( qw/ create register / ) {
        my $rs = execute(
            [
                'runuser', '-u', $self->{'config'}->{'spamd'}->{'user'}, '--',
                'razor-admin', "-home=$razorHome", "-$action"
            ],
            \my $stdout,
            \my $stderr
        );
        debug( $stdout ) if $stdout;
        next unless $rs;

        # Razor registration requires network access to the Razor servers.
        # Don't fail; registration will be retried on next plugin
        # (re)configuration and Razor works without registration.
        if ( $action eq 'register' ) {
            debug( sprintf( "Couldn't register Razor identity: %s", $stderr || 'Unknown error' ));
            next;
        }

        error( $stderr || 'Unknown error' );
        return $rs;
    }

    0;
}

=item _configureHeinleinRuleset( [ $action = 'deconfigure' ] )

 Configure/Deconfigure Heinlein SpamAssassin ruleset

 Param string $action Action to perform (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureHeinleinRuleset
{
    my ( $self, $action ) = @_;
    $action //= 'deconfigure';

    my $cronFile = '/etc/cron.hourly/spamassassin_heinlein-support_de';
    my $c = $self->{'config'}->{'spamassassin'}->{'heinlein_support_ruleset'} // {};

    if ( $action eq 'configure' && $c->{'enabled'} ) {
        my $channel = $c->{'channel'} // 'spamassassin.heinlein-support.de';
        my $sleepTimer = $c->{'sleep_timer'} // 600;
        my $gpgKey = $c->{'gpg_key'} // '';
        $gpgKey =~ s/\s+//g;

        unless ( $channel =~ /^[A-Za-z0-9.-]+$/ && $sleepTimer =~ /^\d+$/ && $gpgKey =~ /^(?:[0-9A-Fa-f]{40})?$/ ) {
            error( 'Invalid heinlein_support_ruleset channel, sleep_timer or gpg_key configuration parameter' );
            return 1;
        }

        # Without GPG key, the channel updates can't be verified (--nogpg):
        # the rules are only protected by TLS/DNS. See config.php.
        my $gpgOptions = length $gpgKey
            ? "--gpgkey $gpgKey --gpghomedir $self->{'config'}->{'spamd'}->{'homedir'}/sa-update-keys"
            : '--nogpg';

        my $file = iMSCP::File->new(
            filename => "$::imscpConfig{'PLUGINS_DIR'}/SpamAssassin/config-templates/spamassassin/spamassassin_heinlein-support_de"
        );
        my $fileContent = $file->get();
        unless ( defined $fileContent ) {
            error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
            return 1;
        }

        $fileContent = process(
            {
                CHANNEL       => $channel,
                GPG_OPTIONS   => $gpgOptions,
                SLEEP_TIMER   => $sleepTimer,
                SPAMD_USER    => $self->{'config'}->{'spamd'}->{'user'},
                SPAMD_HOMEDIR => $self->{'config'}->{'spamd'}->{'homedir'},
                SPAMD_SERVICE => $self->{'_spamd_service'}
            },
            $fileContent
        );

        $file->{'filename'} = $cronFile;
        $file->set( $fileContent );
        my $rs = $file->save();
        $rs ||= $file->owner( $::imscpConfig{'ROOT_USER'}, $::imscpConfig{'ROOT_GROUP'} );
        $rs ||= $file->mode( 0755 );
        return $rs;
    }

    # Remove the channel rules (<homedir>/<sa_version>/spamassassin_heinlein-support_de{,.cf,...})
    #
    # The home directory is owned by the SPAMD(8p) user. The rules are
    # removed as that user, and FIND(1) doesn't follow symlinks.
    local $@;
    eval {
        my $homedir = $self->{'config'}->{'spamd'}->{'homedir'};
        return unless -d $homedir && getpwnam( $self->{'config'}->{'spamd'}->{'user'} );
        $self->_runAsUser(
            $self->{'config'}->{'spamd'}->{'user'},
            'find', $homedir, '-mindepth', '2', '-maxdepth', '2', '-name', 'spamassassin_heinlein-support_de*',
            '-exec', 'rm', '-rf', '--', '{}', '+'
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    return 0 unless -f $cronFile;
    iMSCP::File->new( filename => $cronFile )->delFile();
}

=item _configureSaMaintenance( [ $action = 'deconfigure' ] )

 Enable/Disable SpamAssassin daily maintenance (sa-update, sa-compile, spamd reload)

 On Debian >= 11, the daily maintenance is provided by the
 spamassassin-maintenance.timer systemd unit. Older versions make use of
 the CRON variable in the /etc/default/spamassassin file (see _configureSa()).

 Param string $action Action to perform (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureSaMaintenance
{
    my ( undef, $action ) = @_;
    $action //= 'deconfigure';

    my $serviceMngr = iMSCP::Service->getInstance();
    # iMSCP::Service::hasService() only looks for '.service' units
    return 0 unless $serviceMngr->isSystemd()
        && grep { -f "$_/spamassassin-maintenance.timer" } qw( /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system );

    # Don't use iMSCP::Service::disable() which would mask the unit
    my $rs = execute(
        [ 'systemctl', '--quiet', $action eq 'configure' ? 'enable' : 'disable', '--now', 'spamassassin-maintenance.timer' ],
        \my $stdout,
        \my $stderr
    );
    debug( $stdout ) if $stdout;
    error( sprintf(
        "Couldn't %s the spamassassin-maintenance.timer unit: %s",
        $action eq 'configure' ? 'enable' : 'disable', $stderr || 'Unknown error'
    )) if $rs;
    $rs;
}

=item _configureSpamassMilter( [ $action = 'deconfigure' ] )

 Configure/Deconfigure spamass-milter service

 Param string $action Action to perform (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureSpamassMilter
{
    my ( $self, $action ) = @_;
    $action //= 'deconfigure';

    return 0 if $action eq 'deconfigure' && !-f '/etc/default/spamass-milter';

    my $file = iMSCP::File->new( filename => '/etc/default/spamass-milter' );
    my $fileContent = $file->get();
    unless ( defined $fileContent ) {
        error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
        return 1;
    }

    if ( $action eq 'configure' ) {
        my $c = $self->{'config'}->{'spamass_milter'};
        my $options = $c->{'options'};
        my $spamcFlags;

        # Extract SPAMC(1) flags before adding any option for SPAMASS_MILTER(8)
        # Flags will be re-appended later
        $options =~ s/\Q$spamcFlags\E$// if ( $spamcFlags ) = $options =~ /(\s+--\s+.*)$/;
        $options .= " -i $_" for @{ $c->{'networks'} // [] };
        $options .= ' -I' if $c->{'ignore_auth_sender_msgs'};
        $options .= ' -r ' . $c->{'spam_reject_policy'};
        $options .= $spamcFlags // '';

        $fileContent =~ s/^OPTIONS=.*/OPTIONS="$options"/m or $fileContent .= "OPTIONS=\"$options\"\n";
        $fileContent =~ s/^[#\s]*SOCKET=.*/SOCKET="$c->{'socket_path'}"/m or $fileContent .= "SOCKET=\"$c->{'socket_path'}\"\n";
        $fileContent =~ s/^[#\s]*SOCKETOWNER=.*/SOCKETOWNER="$c->{'socket_owner'}"/m
            or $fileContent .= "SOCKETOWNER=\"$c->{'socket_owner'}\"\n";
        $fileContent =~ s/^[#\s]*SOCKETMODE=.*/SOCKETMODE="$c->{'socket_mode'}"/m
            or $fileContent .= "SOCKETMODE=\"$c->{'socket_mode'}\"\n";
    } else {
        $fileContent =~ s/^OPTIONS=.*/OPTIONS="-u spamass-milter -i 127.0.0.1"/m;
        $fileContent =~ s%^SOCKET=.*%# SOCKET="/var/spool/postfix/spamass/spamass.sock"%m;
        $fileContent =~ s/^SOCKETOWNER=.*/# SOCKETOWNER="postfix:postfix"/m;
        $fileContent =~ s/^SOCKETMODE=.*/# SOCKETMODE="0660"/m;
    }

    $file->set( $fileContent );
    $file->save();
}

=item _getPostfixMilterSocket( $config )

 Get Postfix milter socket (path relative to the Postfix chroot)

 Param hashref $config Plugin configuration
 Return string

=cut

sub _getPostfixMilterSocket
{
    my ( undef, $config ) = @_;

    return undef unless defined $config->{'spamass_milter'}->{'socket_path'};

    ( my $socket = $config->{'spamass_milter'}->{'socket_path'} ) =~ s%^/var/spool/postfix%%;
    "unix:$socket";
}

=item _configurePostfix( [ $action = 'deconfigure' ] )

 Configure/Deconfigure postfix

 Only the milter entries that belong to this plugin are added/removed. Entries
 added by other plugins, such as the OpenDKIM or ClamAV plugins, are left
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
    } grep { defined } uniq(
        $self->_getPostfixMilterSocket( $self->{'config_prev'} ), $self->_getPostfixMilterSocket( $self->{'config'} )
    );

    # Milter macros required by SPAMASS_MILTER(8), in addition to the Postfix
    # default ones. Only those not provided by default are removed on
    # deconfiguration.
    my @milterMacros = ( 'i', 'j', '{daemon_name}', 'v', '{if_name}', '_' );
    my @milterMacrosDefault = $self->_getPostfixDefaultValues( 'milter_connect_macros' );
    my @milterMacrosToRemove = grep { my $m = $_; !grep ( $_ eq $m, @milterMacrosDefault ) } @milterMacros;

    my $rs = $mta->postconf( (
        smtpd_milters     => {
            action => 'remove',
            values => [ @milterRegexps ]
        },
        non_smtpd_milters => {
            action => 'remove',
            values => [ @milterRegexps ]
        },
        ( $action ne 'configure' && @milterMacrosToRemove
            ? ( milter_connect_macros => {
                action => 'remove',
                values => [ @milterMacrosToRemove ]
            } )
            : ()
        )
    ));
    return $rs if $rs || $action ne 'configure';

    my $milterValue = sprintf(
        '{ %s, default_action=%s }',
        $self->_getPostfixMilterSocket( $self->{'config'} ),
        $self->{'config'}->{'spamass_milter'}->{'postfix_milter_default_action'}
    );

    $mta->postconf( (
        smtpd_milters         => {
            action => 'add',
            values => [ $milterValue ],
            before => qr/.*/ # Make sure that SpamAssassin filtering is processed first
        },
        non_smtpd_milters     => {
            action => 'add',
            values => [ $milterValue ],
            before => qr/.*/ # Make sure that SpamAssassin filtering is processed first
        },
        milter_connect_macros => {
            action => 'add',
            values => [ @milterMacros ]
        }
    ));
}

=item _getPostfixDefaultValues( $parameter )

 Get default value of the given Postfix parameter

 Param string $parameter Postfix parameter name
 Return list Parameter values

=cut

sub _getPostfixDefaultValues
{
    my ( undef, $parameter ) = @_;

    my $rs = execute( [ 'postconf', '-dh', $parameter ], \my $stdout, \my $stderr );
    return () if $rs || !defined $stdout;

    split /[\s,]+/, $stdout;
}

=item _registerCronjob( $cronjobId )

 Register the given cronjob

 Param string $cronjobId Cronjob unique identifier
 Return int 0 on success, other on failure

=cut

sub _registerCronjob
{
    my ( $self, $cronjobId ) = @_;

    my %cronjobs = (
        bayes_sa_learn => [ 'BayesSaLearn', $self->{'config'}->{'spamassassin'}->{'Bayes'}->{'cronjob_sa_learn'} ],
        clean_bayes_db => [ 'CleanBayesDb', $self->{'config'}->{'spamassassin'}->{'Bayes'}->{'cronjob_clean_db'} ],
        clean_awl_db   => [ 'CleanAwlDb', $self->{'config'}->{'spamassassin'}->{'AWL'}->{'cronjob_clean_db'} ],
        discover_razor => [ 'DiscoverRazor', { minute => '@weekly' } ]
    );

    exists $cronjobs{$cronjobId} or die( sprintf( 'Unknown cronjob: %s', $cronjobId ));

    my ( $taskId, $schedule ) = @{ $cronjobs{$cronjobId} };
    $schedule //= {};

    Servers::cron->factory()->addTask( {
        TASKID  => "Plugin::SpamAssassin::$taskId",
        MINUTE  => $schedule->{'minute'} // '@daily',
        HOUR    => $schedule->{'hour'} // '*',
        DAY     => $schedule->{'day'} // '*',
        MONTH   => $schedule->{'month'} // '*',
        DWEEK   => $schedule->{'dweek'} // '*',
        COMMAND => "nice -n 15 ionice -c2 -n5 perl $::imscpConfig{'PLUGINS_DIR'}/SpamAssassin/cronjobs/$cronjobId.pl "
            . '>/dev/null 2>&1'
    } );
}

=item _unregisterCronjob( $cronjobId )

 Unregister the given cronjob

 Param string $cronjobId Cronjob unique identifier
 Return int 0 on success, other on failure

=cut

sub _unregisterCronjob
{
    my ( undef, $cronjobId ) = @_;

    Servers::cron->factory()->deleteTask( { TASKID => 'Plugin::SpamAssassin::' . $cronjobId } );
}

=item _getSaDsn( )

 Get SpamAssassin DBI DSN

 Return string

=cut

sub _getSaDsn
{
    my $dbName = "$::imscpConfig{'DATABASE_NAME'}_spamassassin";

    # DBD::MariaDB is supported by SpamAssassin >= 4.0 (Debian >= 12). The
    # DBD::mysql driver isn't installed by default on Debian 13.
    if ( check_install( module => 'DBD::MariaDB', verbose => 0 ) ) {
        # DBD::MariaDB refuses the port attribute when host is 'localhost'
        # (connection through the Unix socket): 'port cannot be specified
        # when host is localhost or embedded'.
        return "DBI:MariaDB:database=$dbName;host=$::imscpConfig{'DATABASE_HOST'}"
            . ( $::imscpConfig{'DATABASE_HOST'} eq 'localhost'
                ? '' : ";port=$::imscpConfig{'DATABASE_PORT'}" );
    }

    "DBI:mysql:$dbName:$::imscpConfig{'DATABASE_HOST'}:$::imscpConfig{'DATABASE_PORT'}";
}

=item _configureSa( [ $action = 'deconfigure ] )

 Configure/Deconfigure SpamAssassin

 Param string $action Action to be performed (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureSa
{
    my ( $self, $action ) = @_;
    $action //= 'deconfigure';

    if ( $action eq 'configure' ) {
        my $file = iMSCP::File->new(
            filename => "$::imscpConfig{'PLUGINS_DIR'}/SpamAssassin/config-templates/spamassassin/00_imscp.cf"
        );
        my $fileContent = $file->get();
        unless ( defined $fileContent ) {
            error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
            return 1;
        }

        my $c = $self->{'config'}->{'spamassassin'};
        my @discardedPrefs;
        # Discard bayes preferences if the SA Bayes plugin is disabled
        push @discardedPrefs, 'use_bayes', 'bayes_auto_learn', 'use_bayes_rules', 'bayes_auto_learn_threshold_nonspam',
            'bayes_auto_learn_threshold_spam' unless $c->{'Bayes'}->{'enabled'};
        # Discard DCC preference if the SA DCC plugin is disabled
        push @discardedPrefs, 'use_dcc' unless $c->{'DCC'}->{'enabled'};
        # Discard Pyzor preference if the SA Pyzor plugin is disabled
        push @discardedPrefs, 'use_pyzor' unless $c->{'Pyzor'}->{'enabled'};
        # Discard Razor2 preference if the SA Razor2 plugin is disabled
        push @discardedPrefs, 'use_razor2' unless $c->{'Razor2'}->{'enabled'};
        # Discard skip_rbl_checks preference if SA RBL checks are disabled
        push @discardedPrefs, 'skip_rbl_checks' unless $c->{'rbl_checks'}->{'enabled'};
        # Discard report_safe preference if SPAM messages are always rejected
        push @discardedPrefs, 'report_safe' if $self->{'config'}->{'spamass_milter'}->{'spam_reject_policy'} == -1;
        # Discard TextCat preferences if the SA TextCat plugin is disabled
        push @discardedPrefs, 'ok_languages' unless $c->{'TextCat'}->{'enabled'};
        # The AWL plugin is either enabled for all users or fully disabled. The
        # TxRep plugin is not supported.
        push @discardedPrefs, 'use_auto_whitelist', 'use_auto_welcomelist', 'use_txrep';

        $fileContent = process(
            {
                SA_DSN                => $self->_getSaDsn(),
                SA_DATABASE_USER      => 'sa_user',
                SA_DATABASE_PASSWORD  => $self->{'_sa_db_passwd'},
                DISCARDED_PREFERENCES => @discardedPrefs
                    ? " AND preference NOT IN(@{ [ join ', ', map qq{'$_'}, @discardedPrefs ] })" : ''
            },
            $fileContent
        );

        if ( $c->{'Bayes'}->{'site_wide'} ) {
            $fileContent =~ s/^[#\s]*(bayes_(?:auto_expire|sql_override_username))/$1/gm;
        } else {
            $fileContent =~ s/^(bayes_(?:auto_expire|sql_override_username))/#$1/gm;
        }

        local $UMASK = 027;
        $file->{'filename'} = '/etc/spamassassin/00_imscp.cf';

        $file->set( $fileContent );
        my $rs = $file->save();
        $rs ||= $file->owner( $::imscpConfig{'ROOT_USER'}, $self->{'config'}->{'spamd'}->{'group'} );
        $rs ||= $file->mode( 0640 );
        return $rs if $rs;

        for my $plugin ( sort keys %{ $c } ) {
            next unless ref $c->{$plugin} eq 'HASH' && defined $c->{$plugin}->{'config_file'};
            $rs = $self->_enableSaPlugin(
                $plugin, $c->{$plugin}->{'config_file'}, $c->{$plugin}->{'enabled'} ? 'enable' : 'disable'
            );
            return $rs if $rs;
        }
    } elsif ( -f '/etc/spamassassin/00_imscp.cf' ) {
        my $rs = iMSCP::File->new( filename => '/etc/spamassassin/00_imscp.cf' )->delFile();
        return $rs if $rs;
    }

    # SPAMD(8p) options
    if ( -f '/etc/default/spamd' ) {
        # Debian >= 12: spamd package, spamd.service unit (no ENABLED/CRON variables)
        my $file = iMSCP::File->new( filename => '/etc/default/spamd' );
        my $fileContent = $file->get();
        unless ( defined $fileContent ) {
            error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
            return 1;
        }

        my $options = $action eq 'configure'
            ? $self->{'config'}->{'spamd'}->{'options'} : '--create-prefs --max-children 5 --helper-home-dir';
        $fileContent =~ s/^OPTIONS=.*/OPTIONS="$options"/m or $fileContent .= "OPTIONS=\"$options\"\n";

        $file->set( $fileContent );
        return $file->save();
    }

    return 0 if $action eq 'deconfigure' && !-f '/etc/default/spamassassin';

    # Legacy layout (Debian < 12)
    my $file = iMSCP::File->new( filename => '/etc/default/spamassassin' );
    my $fileContent = $file->get();
    unless ( defined $fileContent ) {
        error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
        return 1;
    }

    if ( $action eq 'configure' ) {
        $fileContent =~ s/^ENABLED=.*/ENABLED=1/gm;
        $fileContent =~ s/^OPTIONS=.*/OPTIONS="$self->{'config'}->{'spamd'}->{'options'}"/gm;
        $fileContent =~ s/^CRON=.*/CRON=1/gm;
    } else {
        $fileContent =~ s/^ENABLED=.*/ENABLED=0/gm;
        $fileContent =~ s/^OPTIONS=.*/OPTIONS="--create-prefs --max-children 5 --helper-home-dir"/gm;
        $fileContent =~ s/^CRON=.*/CRON=0/gm;
    }

    $file->set( $fileContent );
    $file->save();
}

=item _enableSaPlugin( $plugin, $conffile, $action )

 Enable/Disable the given SpamAssassin plugin in the given SpamAssassin configuration file.

 Param string $plugin Plugin name
 Param string $conffile SpamAssassin configuration file in which the plugin must be enabled/disabled
 Param string $action Action to perform (enable/disable)
 Return int 0 on success, other on failure

=cut

sub _enableSaPlugin
{
    my ( undef, $plugin, $conffile, $action ) = @_;

    unless ( $plugin =~ /^[A-Za-z0-9_]+$/ && $conffile =~ m%^/etc/(?:mail/)?spamassassin/[^/]+\.(?:pre|cf)$% ) {
        error( sprintf( 'Invalid SpamAssassin plugin or configuration file: %s (%s)', $plugin, $conffile ));
        return 1;
    }

    if ( !-f $conffile ) {
        # Nothing to disable
        return 0 if $action eq 'disable';

        error( sprintf( "The %s SpamAssassin configuration file doesn't exist", $conffile ));
        return 1;
    }

    my $file = iMSCP::File->new( filename => $conffile );
    my $fileContent = $file->get();
    unless ( defined $fileContent ) {
        error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
        return 1;
    }

    if ( $action eq 'disable' ) {
        $fileContent =~ s/^(loadplugin\s+Mail::SpamAssassin::Plugin::$plugin)(?=\s|$)/#$1/m;
    } elsif ( !( $fileContent =~ s/^[#\s]*(loadplugin\s+Mail::SpamAssassin::Plugin::$plugin)(?=\s|$)/$1/m ) ) {
        # Plugin line not in file. We add it manually
        $fileContent .= "\nloadplugin Mail::SpamAssassin::Plugin::${plugin}\n";
    }

    $file->set( $fileContent );
    $file->save();
}

=item _setupSaPlugins( )

 Setup SpamAssassin plugins

 Return int 0 on success, other on failure

=cut

sub _setupSaPlugins
{
    my ( $self ) = @_;

    my $c = $self->{'config'}->{'spamassassin'};

    my $rs = $self->_setGlobalSaPref(
        [ 'use_bayes', 'use_bayes_rules', 'bayes_auto_learn' ],
        $c->{'Bayes'}->{'enforced'} ? 1 : 0,
        $c->{'Bayes'}->{'enforced'}
    );
    $rs ||= $self->_setGlobalSaPref( [ 'use_dcc' ], $c->{'DCC'}->{'enforced'} ? 1 : 0, $c->{'DCC'}->{'enforced'} );
    $rs ||= $self->_setGlobalSaPref( [ 'use_pyzor' ], $c->{'Pyzor'}->{'enforced'} ? 1 : 0, $c->{'Pyzor'}->{'enforced'} );
    $rs ||= $self->_setGlobalSaPref( [ 'use_razor2' ], $c->{'Razor2'}->{'enforced'} ? 1 : 0, $c->{'Razor2'}->{'enforced'} );
    $rs ||= $self->_setGlobalSaPref(
        [ 'skip_rbl_checks' ], $c->{'rbl_checks'}->{'enforced'} ? 0 : 1, $c->{'rbl_checks'}->{'enforced'}
    );
    return $rs if $rs;

    if ( $c->{'Bayes'}->{'site_wide'} ) {
        # If the SA Bayes plugin operates at site-wide, we must prevent users to
        # act on threshold-based auto-learning discriminator for SpamAssassin's
        # Bayes subsystem.
        $rs = $self->_setGlobalSaPref( [ 'bayes_auto_learn_threshold_nonspam' ], '0.1', 1 );
        $rs ||= $self->_setGlobalSaPref( [ 'bayes_auto_learn_threshold_spam' ], '12.0', 1 );
        return $rs if $rs;
    }

    $rs = $c->{'AWL'}->{'enabled'} ? $self->_registerCronjob( 'clean_awl_db' ) : $self->cleanAwlDb();
    $rs ||= $self->_registerCronjob( 'clean_bayes_db' ) if $c->{'Bayes'}->{'enabled'} && $c->{'Bayes'}->{'site_wide'};
    $rs ||= $self->_setupPyzor() if $c->{'Pyzor'}->{'enabled'};
    return $rs if $rs || !$c->{'Razor2'}->{'enabled'};

    $rs = $self->_setupRazor();
    $rs ||= $self->_registerCronjob( 'discover_razor' );
}

=item _isRoundcubeAvailable( )

 Is the Roundcube webmail available?

 Return bool TRUE if Roundcube is available, FALSE otherwise

=cut

sub _isRoundcubeAvailable
{
    my ( $self ) = @_;

    # i-MSCP >= 1.5: WEB_MAIL_CLIENT_PACKAGES; older: WEBMAIL_PACKAGES
    my $packages = $::imscpConfig{'WEB_MAIL_CLIENT_PACKAGES'} // $::imscpConfig{'WEBMAIL_PACKAGES'} // '';
    return 0 unless grep ( lc $_ eq 'roundcube', split /\s*,\s*/, $packages );

    -f "$self->{'_rc_dir'}/config/config.inc.php";
}

=item _reloadPanel( )

 Reload the panel (PHP-FPM) service to make Roundcube aware of changes

 Return int 0 on success, other on failure

=cut

sub _reloadPanel
{
    local $@;
    eval { iMSCP::Service->getInstance()->reload( 'imscp_panel' ); };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _installRoundcubePlugins( [ $action = 'uninstall' ] )

 Install/Uninstall third-party Roundcube plugins

 Param string $action Action to perform (install|uninstall)
 Return int 0 on success, other on failure

=cut

sub _installRoundcubePlugins
{
    my ( $self, $action ) = @_;
    $action //= 'uninstall';

    my $pluginsSrcDir = "$::imscpConfig{'PLUGINS_DIR'}/SpamAssassin/roundcube-plugins";
    my $pluginDestDir = "$self->{'_rc_dir'}/plugins";

    local $@;
    eval {
        iMSCP::Dir->new( dirname => "$pluginDestDir/$_" )->remove() for @RC_PLUGINS_3RD_PARTY;
    };
    if ( $@ ) {
        error( $@ );
        return 1
    }

    return 0 unless $action eq 'install';

    for my $pluginName ( @RC_PLUGINS_3RD_PARTY ) {
        next unless $self->{'config'}->{'roundcube'}->{$pluginName}->{'enabled'} && -d "$pluginsSrcDir/$pluginName";

        eval { iMSCP::Dir->new( dirname => "$pluginsSrcDir/$pluginName" )->rcopy( "$pluginDestDir/$pluginName" ); };
        if ( $@ ) {
            error( $@ );
            return 1;
        }

        my $rs = setRights( "$pluginDestDir/$pluginName", {
            user      => $self->{'_panel_user'},
            group     => $self->{'_panel_group'},
            dirmode   => '0550',
            filemode  => '0440',
            recursive => 1
        } );
        return $rs if $rs;
    }

    0;
}

=item _configureRoundcubePlugins( [ $action = 'deconfigure' ] )

 Configure/Deconfigure Roundcube plugins

 The configuration files are written in the Roundcube configuration directory
 as <plugin>.inc.php files. Roundcube loads them when the plugins don't
 provide their own config.inc.php file. The Roundcube core plugin directories
 are therefore never modified.

 Param string $action Action to perform (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureRoundcubePlugins
{
    my ( $self, $action ) = @_;
    $action //= 'deconfigure';

    my $c = $self->{'config'};
    my $bayesLearning = $c->{'roundcube'}->{'markasjunk'}->{'enabled'} && $c->{'spamassassin'}->{'Bayes'}->{'enabled'};

    for my $plugin ( qw / sauserprefs markasjunk / ) {
        my $confFile = "$self->{'_rc_dir'}/config/$plugin.inc.php";

        if ( $action ne 'configure' || !$c->{'roundcube'}->{$plugin}->{'enabled'}
            || ( $plugin eq 'markasjunk' && !$bayesLearning )
        ) {
            if ( -f $confFile ) {
                my $rs = iMSCP::File->new( filename => $confFile )->delFile();
                return $rs if $rs;
            }
            next;
        }

        my $file = iMSCP::File->new(
            filename => "$::imscpConfig{'PLUGINS_DIR'}/SpamAssassin/config-templates/$plugin/config.inc.php"
        );
        my $fileContent = $file->get();
        unless ( defined $fileContent ) {
            error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
            return 1;
        }

        if ( $plugin eq 'sauserprefs' ) {
            $fileContent = process(
                {
                    DATABASE_HOST        => $::imscpConfig{'DATABASE_HOST'},
                    DATABASE_PORT        => $::imscpConfig{'DATABASE_PORT'},
                    SA_DATABASE_NAME     => "$::imscpConfig{'DATABASE_NAME'}_spamassassin",
                    SA_DATABASE_USER     => 'sa_user',
                    SA_DATABASE_PASSWORD => $self->{'_sa_db_passwd'}
                },
                $fileContent
            );

            my @settings = @{ $c->{'roundcube'}->{'sauserprefs'}->{'sauserprefs_dont_override'} // [] };
            my $sa = $c->{'spamassassin'};

            # If SPAM is never tagged, there is not reasons to let user change headers and
            # report related settings through Roundcube sauserprefs plugin
            push @settings, '{headers}', '{report}', 'rewrite_header Subject'
                if $c->{'spamass_milter'}->{'spam_reject_policy'} == -1;
            # Hide Bayes settings in Roundcube sauserprefs plugin if the SA plugin is disabled or enforced
            push @settings, '{bayes}' if !$sa->{'Bayes'}->{'enabled'} || $sa->{'Bayes'}->{'enforced'};
            # If the SA Bayes plugin operates on a site-wide basis, we must
            # prevent users to act on threshold-based auto-learning
            # discriminator for SpamAssassin's Bayes subsystem.
            push @settings, 'bayes_auto_learn_threshold_nonspam', 'bayes_auto_learn_threshold_spam'
                if $sa->{'Bayes'}->{'site_wide'};

            if ( ( !$sa->{'DCC'}->{'enabled'} || $sa->{'DCC'}->{'enforced'} )
                && ( !$sa->{'Pyzor'}->{'enabled'} || $sa->{'Pyzor'}->{'enforced'} )
                && ( !$sa->{'Razor2'}->{'enabled'} || $sa->{'Razor2'}->{'enforced'} )
                && ( !$sa->{'rbl_checks'}->{'enabled'} || $sa->{'rbl_checks'}->{'enforced'} )
            ) {
                # None of plugins for which parameters are settable trough Roundcube sauserprefs plugin is enabled.
                # Therefore, there is no reasons to show them in the plugin interface
                push @settings, '{tests}';
            } else {
                # Hide DCC setting in Roundcube sauserprefs plugin if the SA plugin is disabled or enforced
                push @settings, 'use_dcc' if !$sa->{'DCC'}->{'enabled'} || $sa->{'DCC'}->{'enforced'};
                # Hide Pyzor setting in Roundcube sauserprefs plugin if the SA plugin is disabled or enforced
                push @settings, 'use_pyzor' if !$sa->{'Pyzor'}->{'enabled'} || $sa->{'Pyzor'}->{'enforced'};
                # Hide Razor2 setting in Roundcube sauserprefs plugin if the SA plugin is disabled or enforced
                push @settings, 'use_razor2' if !$sa->{'Razor2'}->{'enabled'} || $sa->{'Razor2'}->{'enforced'};
                # Hide RBL checks setting in Roundcube sauserprefs plugin if SA RBL checks are disabled or enforced
                push @settings, 'skip_rbl_checks' if !$sa->{'rbl_checks'}->{'enabled'} || $sa->{'rbl_checks'}->{'enforced'};
            }

            # Hide TextCat setting in Roundcube sauserprefs plugin if the SA plugin is disabled or enforced
            push @settings, 'ok_languages' if !$sa->{'TextCat'}->{'enabled'} || $sa->{'TextCat'}->{'enforced'};

            for my $setting ( @settings ) {
                # Values end in a PHP single-quoted string
                $setting =~ s/(['\\])/\\$1/g;
            }

            $fileContent =~ s/\Q{SAUSERPREFS_DONT_OVERRIDE}\E/@{ [ join ",\n    ", map qq{'$_'}, uniq @settings ] }/g;
        } else {
            $fileContent = process( { SA_LEARN_DIR => $self->{'_sa_learn_dir'} }, $fileContent );
        }

        # The Roundcube configuration directory is owned by the panel user.
        # Never write through a symlink.
        if ( -l $confFile && !unlink( $confFile ) ) {
            error( sprintf( "Couldn't remove the %s symlink: %s", $confFile, $! ));
            return 1;
        }

        local $UMASK = 0227;
        $file->{'filename'} = $confFile;
        $file->set( $fileContent );
        my $rs = $file->save();
        $rs ||= $file->owner( $self->{'_panel_user'}, $self->{'_panel_group'} );
        $rs ||= $file->mode( 0440 );
        return $rs if $rs;
    }

    # Learning directories (dir_learn driver of the markasjunk Roundcube plugin)
    if ( $action eq 'configure' && $bayesLearning ) {
        local $@;
        eval {
            # The directories live in the panel user owned plugin directory.
            # They are created as the panel user (never chown/chmod as root
            # through a path controlled by that user).
            my @dirs = ( $self->{'_sa_learn_dir'}, "$self->{'_sa_learn_dir'}/spam", "$self->{'_sa_learn_dir'}/ham" );
            $self->_runAsUser( $self->{'_panel_user'}, 'mkdir', '-p', '-m', '0700', '--', @dirs );
            $self->_runAsUser( $self->{'_panel_user'}, 'chmod', '0700', '--', @dirs );
        };
        if ( $@ ) {
            error( $@ );
            return 1;
        }

        return $self->_registerCronjob( 'bayes_sa_learn' );
    }

    # Learn pending messages, if any (and remove them)
    return 0 unless -d $self->{'_sa_learn_dir'};
    $self->bayesSaLearn();
}

=item _enableRoundcubePlugins( [ $action = 'disable' ] )

 Enable/Disable Roundcube Plugins

 Param string $action Action to perform (enable|disable)
 Return int 0 on success, other on failure

=cut

sub _enableRoundcubePlugins
{
    my ( $self, $action ) = @_;
    $action //= 'disable';

    my $confFilename;
    if ( -f "$self->{'_rc_dir'}/config/config.inc.php" ) {
        $confFilename = "$self->{'_rc_dir'}/config/config.inc.php";
    } elsif ( -f "$::imscpConfig{'GUI_PUBLIC_DIR'}/tools/webmail/config/config.inc.php" ) {
        # Legacy location
        $confFilename = "$::imscpConfig{'GUI_PUBLIC_DIR'}/tools/webmail/config/config.inc.php";
    } else {
        return 0 if $action eq 'disable';
        error( "Couldn't find Roundcube configuration file" );
        return 1;
    }

    # The Roundcube configuration directory is owned by the panel user.
    # Never write through a symlink.
    if ( -l $confFilename ) {
        error( sprintf( 'The %s file is a symlink. Refusing to process it.', $confFilename ));
        return 1;
    }

    my $file = iMSCP::File->new( filename => $confFilename );
    my $fileContent = $file->get();
    unless ( defined $fileContent ) {
        error( sprintf( "Couldn't read the %s file", $file->{'filename'} ));
        return 1;
    }

    $fileContent = replaceBloc(
        qr/(:?^\n)?\Q# Begin Plugin::SpamAssassin\E\n/m, qr/\Q# Ending Plugin::SpamAssassin\E\n/, '', $fileContent
    );

    if ( $action eq 'enable' ) {
        my @plugins;
        push @plugins, 'sauserprefs' if $self->{'config'}->{'roundcube'}->{'sauserprefs'}->{'enabled'};
        push @plugins, 'markasjunk' if $self->{'config'}->{'roundcube'}->{'markasjunk'}->{'enabled'}
            && $self->{'config'}->{'spamassassin'}->{'Bayes'}->{'enabled'};

        $fileContent .= <<"EOF" if @plugins;

# Begin Plugin::SpamAssassin
\$config['plugins'] = array_values(array_unique(array_merge(
    isset(\$config['plugins']) ? (array) \$config['plugins'] : [],
    [@{ [ join ', ', map qq/'$_'/, @plugins ] }]
)));
# Ending Plugin::SpamAssassin
EOF
    }

    $file->set( $fileContent );
    $file->save();
}

=item _setGlobalSaPref( \@preferences, $value [, $enforce = FALSE ] )

 Update the given global SA preferences and enforce them if requested

 Param arrayref \@preference Global List of SA preference names
 Param string $value Global SA preference value
 Param bool $enforce Whether or not the Global SA preference must be enforced
 Return int 0 on success, other on failure

=cut

sub _setGlobalSaPref
{
    my ( undef, $preferences, $value, $enforce ) = @_;

    my $dbh = iMSCP::Database->factory();
    my $dbi = $dbh->getRawDb();
    my $oldDb;

    local $@;
    eval {
        local $dbi->{'RaiseError'} = 1;
        $oldDb = $dbh->useDatabase( "$::imscpConfig{'DATABASE_NAME'}_spamassassin" );

        for my $preference ( @{ $preferences } ) {
            $dbi->do( 'DELETE FROM userpref WHERE username <> ? AND preference = ?', undef, '$GLOBAL', $preference ) if $enforce;
            $dbi->do( 'UPDATE userpref SET value = ? WHERE username = ? AND preference = ?', undef, $value, '$GLOBAL', $preference );
        }

        $dbh->useDatabase( $oldDb ) if $oldDb;
    };
    if ( $@ ) {
        $dbh->useDatabase( $oldDb ) if $oldDb;
        error( $@ );
        return 1;
    }

    0;
}

=item _createSaSqlUser( )

 Create SpamAssassin SQL user

 Return int 0 on success, other on failure

=cut

sub _createSaSqlUser
{
    my ( $self ) = @_;

    my $dbi = iMSCP::Database->factory()->getRawDb();

    local $@;
    eval {
        $self->{'_sa_db_passwd'} = randomStr( 16, ALNUM );
        local $dbi->{'RaiseError'} = 1;
        my $dbName = $::imscpConfig{'DATABASE_NAME'} . '_spamassassin';
        $dbi->selectrow_array(
            'SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?', undef, $dbName
        ) or die( sprintf( "Couldn't find the `%s' SQL database.", $dbName ));

        my $sqld = Servers::sqld->factory();
        $sqld->dropUser( 'sa_user', $::imscpConfig{'DATABASE_USER_HOST'} );
        $sqld->createUser( 'sa_user', $::imscpConfig{'DATABASE_USER_HOST'}, $self->{'_sa_db_passwd'} );

        my $quotedDbName = $dbi->quote_identifier( $dbName );
        $dbi->do(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON $quotedDbName.* TO ?\@?",
            undef, 'sa_user', $::imscpConfig{'DATABASE_USER_HOST'}
        );
    };
    if ( $@ ) {
        error( sprintf( "Couldn't create SpamAssassin SQL user: %s", $@ ));
        return 1;
    }

    0;
}

=item _installSaPlugins( [ $action = 'uninstall' ] )

 Install/Uninstall 3rd-party SpamAssassin plugins

 Param string $action Action to perform (install|uninstall)
 Return int 0 on success, other on failure

=cut

sub _installSaPlugins
{
    my ( $self, $action ) = @_;
    $action //= 'uninstall';

    # The 3rd-party DecodeShortURLs plugin (plugin versions < 2.1.0) is
    # superseded by the SpamAssassin 4.0 DecodeShortURLs plugin
    for my $file ( '/etc/spamassassin/DecodeShortURLs.cf', '/etc/spamassassin/DecodeShortURLs.pm' ) {
        next unless -f $file;
        my $rs = iMSCP::File->new( filename => $file )->delFile();
        return $rs if $rs;
    }

    for my $plugin ( qw/ iXhash2 / ) {
        for my $ext ( qw/ cf pm / ) {
            if ( $action eq 'install' && $self->{'config'}->{'spamassassin'}->{$plugin}->{'enabled'} ) {
                my $file = iMSCP::File->new(
                    filename => "$::imscpConfig{'PLUGINS_DIR'}/SpamAssassin/spamassassin-plugins/$plugin/$plugin.$ext"
                );
                my $rs = $file->copyFile( "/etc/spamassassin/$plugin.$ext", { preserve => 'no' } );
                return $rs if $rs;

                $file->{'filename'} = "/etc/spamassassin/$plugin.$ext";
                $rs = $file->owner( $::imscpConfig{'ROOT_USER'}, $::imscpConfig{'ROOT_GROUP'} );
                $rs ||= $file->mode( 0644 );
                return $rs if $rs;
                next;
            }

            next unless -f "/etc/spamassassin/$plugin.$ext";
            my $rs = iMSCP::File->new( filename => "/etc/spamassassin/$plugin.$ext" )->delFile();
            return $rs if $rs;
        }
    }

    0;
}

=back

=head1 FUNCTIONS (symlink-safe file operations)

=over 4

=item _pinDirectory( $dir, $uid )

 Change the current directory to the given directory, making sure that it is
 a real directory (not a symlink) owned by the given UID (or by root)

 Once the current directory is set, it refers to the directory inode: it
 can't be redirected anymore, even if the path is changed afterwards.

 Param string $dir Directory path
 Param int $uid Expected owner UID
 Return bool TRUE if the directory has been pinned, FALSE if it doesn't exist, die on failure

=cut

sub _pinDirectory
{
    my ( $dir, $uid ) = @_;

    my @lst = lstat $dir or return 0;
    die( sprintf( 'Refusing to process %s: symlink', $dir )) if -l _;
    die( sprintf( 'Refusing to process %s: not a directory', $dir )) unless -d _;
    die( sprintf( 'Refusing to process %s: unexpected owner (UID %d)', $dir, $lst[4] )) unless $lst[4] == $uid || $lst[4] == 0;

    chdir( $dir ) or die( sprintf( "Couldn't change directory to %s: %s", $dir, $! ));
    my @st = stat '.';
    $st[0] == $lst[0] && $st[1] == $lst[1] or die( sprintf( '%s has been replaced. Aborting.', $dir ));
    1;
}

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

=back

=head1 AUTHORS

 Laurent Declercq <l.declercq@nuxwin.com>
 Sascha Bay <info@space2place.de>
 Rene Schuster <mail@reneschuster.de>

=cut

1;
__END__
