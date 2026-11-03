=head1 NAME

 Package::WebmailClients::Roundcube::Handler - i-MSCP Roundcube package handler

=cut

# i-MSCP - internet Multi Server Control Panel
# Copyright (C) 2010-2019 Laurent Declercq <l.declercq@nuxwin.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

package Package::WebmailClients::Roundcube::Handler;

use strict;
use warnings;
use Digest::SHA;
use File::Basename 'basename';
use File::Spec;
use iMSCP::Boolean;
use iMSCP::Crypt qw/ decryptRijndaelCBC encryptRijndaelCBC randomStr /;
use iMSCP::Cwd '$CWD';
use iMSCP::Database;
use iMSCP::Debug qw/ debug error /;
use iMSCP::Dir;
use iMSCP::EventManager;
use iMSCP::Execute 'execute';
use iMSCP::File;
use iMSCP::Getopt;
use iMSCP::Rights 'setRights';
use iMSCP::TemplateParser qw/ getBloc replaceBloc process /;
use LWP::UserAgent;
use Servers::sqld;
use Scalar::Defer;
use parent 'Common::Object';

=head1 DESCRIPTION

 i-MSCP Roundcube package handler.

 The Roundcube Webmail application is not shipped with this package. The
 pinned upstream release (see %UPSTREAM below) is downloaded from the official
 Roundcube GitHub release page at setup time, verified against the pinned
 SHA-256 checksum and extracted into the
 <GUI_ROOT_DIR>/vendor/imscp/roundcube/roundcubemail directory.

 The '-complete' tarball ships with all PHP and Javascript dependencies, hence
 neither composer nor install-jsdeps.sh need to be run.

=cut

# Pinned upstream release. Roundcube 1.6.x is the last series that supports
# PHP 7.3 (the i-MSCP control panel PHP version).
# Checksum taken from the GitHub release asset digest; release tarball
# signature verified with the Roundcube signing key
# (F3E4C04BB3DB5D4215C45F7F5AB2BAA141C4F7D5).
my %UPSTREAM = (
    version => '1.6.20',
    url     => 'https://github.com/roundcube/roundcubemail/releases/download/1.6.20/roundcubemail-1.6.20-complete.tar.gz',
    sha256  => '46919c70c85609b57038903c4ecc4e1d7fa4e14c535fe5b14192d778dcd4a1ee'
);

=head1 PUBLIC METHODS

=over 4

=item preinstall( )

 Pre-installation tasks

 Return int 0 on success, other on failure

=cut

sub preinstall
{
    my ( $self ) = @_;

    local $CWD = $::imscpConfig{'GUI_ROOT_DIR'};

    my $rs = $self->_installUpstream();
    # Needed for scripts execution
    $rs ||= $self->setGuiPermissions();
    return $rs if $rs;

    $self->{'events'}->register(
        'afterFrontEndBuildConfFile', \&afterFrontEndBuildConfFile
    );
}

=item install( )

 Installation tasks

 Return int 0 on success, other on failure

=cut

sub install
{
    my ( $self ) = @_;

    local $CWD = $::imscpConfig{'GUI_ROOT_DIR'};

    local $@;
    eval {
        for my $dir ( "$CWD/data/logs/roundcube", "$CWD/data/tmp" ) {
            iMSCP::Dir->new( dirname => $dir )->make( {
                user           => $::imscpConfig{'SYSTEM_USER_PREFIX'}
                    . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
                group          => $::imscpConfig{'SYSTEM_USER_PREFIX'}
                    . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
                mode           => 0750,
                fixpermissions => $dir =~ /roundcube$/ ? TRUE : FALSE
            } );
        }
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    my $rs = $self->_buildConfigFiles();
    $rs ||= $self->_buildHttpdConfigFile();
    # Need to be done before database setup as the Roundcube scripts
    # rely on SQL user to create/update database.
    $rs ||= $self->_setupSqlUser();
    $rs ||= $self->_setupDatabase();
}

=item postinstall( )

 Post-installation tasks

 Return int 0 on success, other on failure

=cut

sub postinstall
{
    local $CWD = $::imscpConfig{'GUI_ROOT_DIR'};

    if ( -l "$CWD/public/tools/roundcube" ) {
        my $rs = iMSCP::File->new(
            filename => "$CWD/public/tools/roundcube"
        )->delFile();
        return $rs if $rs;
    }

    unless ( symlink( File::Spec->abs2rel(
        "$CWD/vendor/imscp/roundcube/roundcubemail/public_html",
        "$CWD/public/tools"
    ),
        "$CWD/public/tools/roundcube"
    ) ) {
        error( sprintf(
            "Couldn't create symlink for the Roundcube webmail: %s", $!
        ));
        return 1;
    }

    0;
}

=item uninstall( )

 Uninstallation tasks

 Return int 0 on success, other on failure

=cut

sub uninstall
{
    my ( $self ) = @_;

    local $CWD = $::imscpConfig{'GUI_ROOT_DIR'};

    if ( -l "$CWD/public/tools/roundcube" ) {
        my $rs = iMSCP::File->new(
            filename => "$CWD/public/tools/roundcube"
        )->delFile();
        return $rs if $rs;
    }

    if ( -f '/etc/nginx/imscp_roundcube.conf' ) {
        my $rs = iMSCP::File->new(
            filename => '/etc/nginx/imscp_roundcube.conf'
        )->delFile();
        return $rs if $rs;
    }

    for my $dir ( 'cron.d', 'logrotate.d' ) {
        next unless -f "/etc/$dir/imscp_roundcube";

        my $rs = iMSCP::File->new(
            filename => "/etc/$dir/imscp_roundcube"
        )->delFile();
        return $rs if $rs;
    }

    local $@;
    eval {
        iMSCP::Dir->new( dirname => "$CWD/data/logs/roundcube" )->remove();
        iMSCP::Dir->new( dirname => "$CWD/vendor/imscp/roundcube/roundcubemail" )->remove();
        iMSCP::Dir->new( dirname => $self->_getCacheDir())->remove();

        $self->{'dbh'}->do(
            "DROP DATABASE IF EXISTS `@{ [ $::imscpConfig{'DATABASE_NAME'} . '_roundcube' ] }`"
        );

        my ( $databaseUser ) = @{ $self->{'dbh'}->selectcol_arrayref(
            "SELECT `value` FROM `config` WHERE `name` = 'ROUNDCUBE_SQL_USER'"
        ) };

        if ( defined $databaseUser ) {
            $databaseUser = decryptRijndaelCBC(
                $::imscpDBKey, $::imscpDBiv, $databaseUser
            );

            for my $host (
                $::imscpOldConfig{'DATABASE_USER_HOST'},
                $::imscpConfig{'DATABASE_USER_HOST'}
            ) {
                next unless length $host;
                Servers::sqld->factory()->dropUser( $databaseUser, $host );
            }
        }

        $self->{'dbh'}->do(
            "DELETE FROM `config` WHERE `name` LIKE 'ROUNDCUBE_%'"
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item setGuiPermissions

 Set GUI permissions

 Return int 0 on success, other on failure

=cut

sub setGuiPermissions
{
    local $CWD = $::imscpConfig{'GUI_ROOT_DIR'};

    return 0 unless -d "$CWD/vendor/imscp/roundcube/roundcubemail/bin";

    setRights( "$CWD/vendor/imscp/roundcube/roundcubemail/bin", {
        dirmode   => '0750',
        filemode  => '0750',
        recursive => TRUE
    } );
}

=item deleteMail( \%moduleData )

 Process deleteMail tasks
 Param hashref \%moduleData Data as provided by the Mail module
 Return int 0 on success, other on failure

=cut

sub deleteMail
{
    my ( $self, $moduleData ) = @_;

    return 0 unless $moduleData->{'MAIL_TYPE'} =~ /_mail/;

    local $@;
    eval {
        $self->{'dbh'}->do(
            "
                DELETE FROM `@{ [ $::imscpConfig{'DATABASE_NAME'} . '_roundcube' ] }`.`users`
                WHERE `username` = ?
            ",
            undef,
            $moduleData->{'MAIL_ADDR'}
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=back

=head1 EVENT LISTENERS

=over 4

=item afterFrontEndBuildConfFile( )

 Event listener that injects Httpd configuration for Roundcube into the i-MSCP
 control panel Nginx vhost files

 Return int 0 on success, other on failure

=cut

sub afterFrontEndBuildConfFile
{
    my ( $tplContent, $tplName ) = @_;

    return 0 unless grep ( $_ eq $tplName, qw/
        00_master.nginx 00_master_ssl.nginx
    /);

    ${ $tplContent } = replaceBloc(
        "# SECTION custom BEGIN.\n",
        "# SECTION custom END.\n",
        "    # SECTION custom BEGIN.\n"
            . getBloc(
                "# SECTION custom BEGIN.\n",
                "# SECTION custom END.\n",
                ${ $tplContent }
            )
            . "    include imscp_roundcube.conf;\n"
            . "    # SECTION custom END.\n",
        ${ $tplContent }
    );

    0;
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 Initialize instance

 Return Package::WebmailClients::Roundcube::Handler

=cut

sub _init
{
    my ( $self ) = @_;

    $self->{'events'} = iMSCP::EventManager->getInstance();
    $self->{'dbh'} = lazy { iMSCP::Database->factory()->getRawDb(); };
    $self;
}

=item _getCacheDir( )

 Get directory in which upstream release archives are cached

 Return string

=cut

sub _getCacheDir
{
    "$::imscpConfig{'GUI_ROOT_DIR'}/data/persistent/addons/roundcube";
}

=item _installUpstream( )

 Download, verify and install the pinned upstream Roundcube release into the
 <GUI_ROOT_DIR>/vendor/imscp/roundcube/roundcubemail directory

 The installation is skipped if the expected release is already installed.

 Return int 0 on success, other on failure

=cut

sub _installUpstream
{
    my ( $self ) = @_;

    my $pkgDir = "$::imscpConfig{'GUI_ROOT_DIR'}/vendor/imscp/roundcube";
    my $appDir = "$pkgDir/roundcubemail";
    my $stamp = "$UPSTREAM{'version'} $UPSTREAM{'sha256'}";
    my $ug = $::imscpConfig{'SYSTEM_USER_PREFIX'}
        . $::imscpConfig{'SYSTEM_USER_MIN_UID'};

    if ( -f "$appDir/.imscp-upstream" && -f "$appDir/index.php" ) {
        my $curStamp = iMSCP::File->new(
            filename => "$appDir/.imscp-upstream"
        )->get() // '';
        chomp( $curStamp );
        if ( $curStamp eq $stamp ) {
            debug( sprintf(
                'Roundcube %s is already installed. Skipping download.',
                $UPSTREAM{'version'}
            ));
            return 0;
        }
    }

    local $@;
    eval {
        -d $pkgDir or die( sprintf(
            "The %s directory doesn't exist. The imscp/roundcube composer package is not installed.",
            $pkgDir
        ));

        # Download (or reuse cached) upstream archive and verify its checksum
        my $cacheDir = $self->_getCacheDir();
        iMSCP::Dir->new( dirname => $cacheDir )->make( {
            user  => $ug,
            group => $ug,
            mode  => 0750
        } );
        my $archive = "$cacheDir/" . basename( $UPSTREAM{'url'} );

        unless ( -f $archive
            && _sha256( $archive ) eq $UPSTREAM{'sha256'}
        ) {
            unlink( $archive );
            debug( sprintf( 'Downloading %s', $UPSTREAM{'url'} ));
            my $response = LWP::UserAgent->new(
                agent     => "iMSCP/$::imscpConfig{'Version'}",
                timeout   => 60,
                env_proxy => TRUE
            )->get( $UPSTREAM{'url'}, ':content_file' => "$archive.part" );
            unless ( $response->is_success ) {
                unlink( "$archive.part" );
                die( sprintf(
                    "Couldn't download the Roundcube %s release archive from %s: %s",
                    $UPSTREAM{'version'}, $UPSTREAM{'url'}, $response->status_line
                ));
            }

            my $sha256 = _sha256( "$archive.part" );
            unless ( $sha256 eq $UPSTREAM{'sha256'} ) {
                unlink( "$archive.part" );
                die( sprintf(
                    "Checksum mismatch for the Roundcube %s release archive (expected SHA-256: %s, got: %s)",
                    $UPSTREAM{'version'}, $UPSTREAM{'sha256'}, $sha256
                ));
            }

            rename( "$archive.part", $archive ) or die( sprintf(
                "Couldn't rename %s.part to %s: %s", $archive, $archive, $!
            ));
        }

        # Extract the archive into a staging directory
        my $newDir = "$pkgDir/.roundcubemail.new";
        my $oldDir = "$pkgDir/.roundcubemail.old";
        iMSCP::Dir->new( dirname => $_ )->remove() for $newDir, $oldDir;
        iMSCP::Dir->new( dirname => $newDir )->make();

        my $rs = execute(
            [
                '/bin/tar', '--extract', '--gzip',
                '--file', $archive,
                '--directory', $newDir,
                '--strip-components=1',
                '--no-same-owner',
                '--no-same-permissions'
            ],
            \my $stdout,
            \my $stderr
        );
        debug( $stdout ) if length $stdout;
        $rs == 0 or die( sprintf(
            "Couldn't extract the Roundcube %s release archive: %s",
            $UPSTREAM{'version'}, $stderr || 'Unknown error'
        ));

        -f "$newDir/index.php" && -d "$newDir/public_html" && -d "$newDir/vendor" or die(
            "Unexpected Roundcube release archive layout."
        );

        # Carry over third-party plugins (e.g. those installed by the i-MSCP
        # RoundcubePlugins plugin) from the previous installation
        if ( -d "$appDir/plugins" ) {
            for my $plugin ( iMSCP::Dir->new( dirname => "$appDir/plugins" )->getDirs() ) {
                next if -e "$newDir/plugins/$plugin";
                debug( sprintf( 'Keeping the %s Roundcube plugin', $plugin ));
                iMSCP::Dir->new( dirname => "$appDir/plugins/$plugin" )->rcopy(
                    "$newDir/plugins/$plugin", { preserve => 'yes' }
                );
            }
        }

        my $stampFile = iMSCP::File->new( filename => "$newDir/.imscp-upstream" );
        $stampFile->set( "$stamp\n" );
        $stampFile->save() == 0 or die(
            "Couldn't write the $newDir/.imscp-upstream file"
        );

        setRights( $newDir, {
            user      => $ug,
            group     => $ug,
            dirmode   => '0750',
            filemode  => '0640',
            recursive => TRUE
        } ) == 0 or die( "Couldn't set permissions on $newDir" );

        # Swap directories
        if ( -d $appDir ) {
            rename( $appDir, $oldDir ) or die( sprintf(
                "Couldn't rename %s to %s: %s", $appDir, $oldDir, $!
            ));
        }
        rename( $newDir, $appDir ) or die( sprintf(
            "Couldn't rename %s to %s: %s", $newDir, $appDir, $!
        ));
        iMSCP::Dir->new( dirname => $oldDir )->remove();
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _sha256( $file )

 Compute SHA-256 digest of the given file

 Param string $file File path
 Return string Hex digest, die on failure

=cut

sub _sha256
{
    my ( $file ) = @_;

    Digest::SHA->new( 256 )->addfile( $file, 'b' )->hexdigest();
}

=item _buildConfigFiles( )

 Build Roundcube configuration files

 Return int 0 on success, other on failure

=cut

sub _buildConfigFiles
{
    my ( $self ) = @_;

    local $@;
    my $rs = eval {
        my %config = @{ $self->{'dbh'}->selectcol_arrayref(
            "
                SELECT `name`, `value`
                FROM `config`
                WHERE `name`
                LIKE 'ROUNDCUBE_%'
            ",
            { Columns => [ 1, 2 ] }
        ) };

        ( $config{'ROUNDCUBE_DES_KEY'} = decryptRijndaelCBC(
            $::imscpDBKey, $::imscpDBiv, $config{'ROUNDCUBE_DES_KEY'} // ''
        ) || randomStr( 24, iMSCP::Crypt::ALPHA64 ) );

        # The des_key must be exactly 24 bytes long
        $config{'ROUNDCUBE_DES_KEY'} = randomStr( 24, iMSCP::Crypt::ALPHA64 )
            unless length $config{'ROUNDCUBE_DES_KEY'} == 24;

        ( $config{'ROUNDCUBE_SQL_USER'} = decryptRijndaelCBC(
            $::imscpDBKey, $::imscpDBiv, $config{'ROUNDCUBE_SQL_USER'} // ''
        ) || 'roundcube_' . randomStr( 6, iMSCP::Crypt::ALNUM ) );

        ( $config{'ROUNDCUBE_SQL_USER_PASSWD'} = decryptRijndaelCBC(
            $::imscpDBKey,
            $::imscpDBiv,
            $config{'ROUNDCUBE_SQL_USER_PASSWD'} // ''
        ) || randomStr( 16, iMSCP::Crypt::ALNUM ) );

        (
            $self->{'_roundcube_sql_user'},
            $self->{'_roundcube_control_user_passwd'}
        ) = (
            $config{'ROUNDCUBE_SQL_USER'}, $config{'ROUNDCUBE_SQL_USER_PASSWD'}
        );

        # Save generated values in database (encrypted)
        $self->{'dbh'}->do(
            '
                INSERT INTO `config` (`name`,`value`)
                VALUES (?,?),(?,?),(?,?)
                ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)
            ',
            undef,
            'ROUNDCUBE_DES_KEY',
            encryptRijndaelCBC(
                $::imscpDBKey, $::imscpDBiv, $config{'ROUNDCUBE_DES_KEY'}
            ),
            'ROUNDCUBE_SQL_USER',
            encryptRijndaelCBC(
                $::imscpDBKey, $::imscpDBiv, $config{'ROUNDCUBE_SQL_USER'}
            ),
            'ROUNDCUBE_SQL_USER_PASSWD',
            encryptRijndaelCBC(
                $::imscpDBKey,
                $::imscpDBiv,
                $config{'ROUNDCUBE_SQL_USER_PASSWD'}
            )
        );

        # Roundcube plugins to enable. The managesieve and password plugins
        # are only relevant with the Dovecot IMAP/POP server (ManageSieve
        # service and SQL passdb on the i-MSCP mail_users table).
        my @plugins = qw/ archive zipdownload /;
        push @plugins, qw/ managesieve password /
            if ::setupGetQuestion( 'PO_SERVER' ) eq 'dovecot';
        $self->{'events'}->trigger(
            'beforeRoundcubeBuildPluginList', \@plugins
        );

        my $data = {
            DES_KEY             => $config{'ROUNDCUBE_DES_KEY'},
            DATABASE_HOSTNAME   => ::setupGetQuestion( 'DATABASE_HOST' ),
            DATABASE_PORT       => ::setupGetQuestion( 'DATABASE_PORT' ),
            DATABASE_NAME       => ::setupGetQuestion( 'DATABASE_NAME' )
                . '_roundcube',
            IMSCP_DATABASE_NAME => ::setupGetQuestion( 'DATABASE_NAME' ),
            DATABASE_USER       => _urlencode( $config{'ROUNDCUBE_SQL_USER'} ),
            DATABASE_PASSWORD   => _urlencode( $config{'ROUNDCUBE_SQL_USER_PASSWD'} ),
            LOG_DIR             => $CWD . '/data/logs/roundcube/',
            TMP_DIR             => $CWD . '/data/tmp/',
            PLUGINS             => join( ',', @plugins )
        };

        my $rs = $self->{'events'}->trigger(
            'onLoadTemplate', 'roundcube', 'config.inc.php', \my $cfgTpl, $data
        );
        return $rs if $rs;

        unless ( defined $cfgTpl ) {
            $cfgTpl = iMSCP::File->new(
                filename => "$CWD/vendor/imscp/roundcube/src/config.inc.php"
            )->get();
            return 1 unless defined $cfgTpl;
        }

        $cfgTpl = process( $data, $cfgTpl );

        my $file = iMSCP::File->new(
            filename => "$CWD/vendor/imscp/roundcube/roundcubemail/config/config.inc.php"
        );
        $file->set( $cfgTpl );
        $rs = $file->save();
        $rs ||= $file->owner(
            $::imscpConfig{'SYSTEM_USER_PREFIX'} . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
            $::imscpConfig{'SYSTEM_USER_PREFIX'} . $::imscpConfig{'SYSTEM_USER_MIN_UID'}
        );
        $rs ||= $file->mode( 0640 );
        return $rs if $rs;

        # Cron and logrotate configuration files
        for my $dir ( 'cron.d', 'logrotate.d' ) {
            next unless -f "$CWD/vendor/imscp/roundcube/src/$dir/imscp_roundcube";

            my $fileC = iMSCP::File->new(
                filename => "$CWD/vendor/imscp/roundcube/src/$dir/imscp_roundcube"
            )->getAsRef();
            return 1 unless defined $fileC;

            ${ $fileC } = process(
                {
                    GUI_ROOT_DIR => $CWD,
                    USER         => $::imscpConfig{'SYSTEM_USER_PREFIX'}
                        . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
                    GROUP        => $::imscpConfig{'SYSTEM_USER_PREFIX'}
                        . $::imscpConfig{'SYSTEM_USER_MIN_UID'}
                },
                ${ $fileC }
            );

            $file = iMSCP::File->new(
                filename => "/etc/$dir/imscp_roundcube"
            );
            $file->set( ${ $fileC } );
            $rs = $file->save();
            return $rs if $rs;
        }

        0;
    };
    if ( $@ ) {
        error( $@ );
        $rs = 1;
    }

    $rs;
}

=item _urlencode( $string )

 URL-encode the given string (for use in Roundcube DSNs)

 Param string $string
 Return string

=cut

sub _urlencode
{
    my ( $string ) = @_;

    $string =~ s/([^A-Za-z0-9\-._~])/sprintf( '%%%02X', ord( $1 ) )/ge;
    $string;
}

=item _buildHttpdConfigFile( )

 Build httpd configuration file for Roundcube

 Return int 0 on success, other on failure

=cut

sub _buildHttpdConfigFile
{
    my $rs = iMSCP::File->new(
        filename => "$CWD/vendor/imscp/roundcube/src/nginx.conf"
    )->copyFile( '/etc/nginx/imscp_roundcube.conf' );
    return $rs if $rs;

    my $file = iMSCP::File->new(
        filename => '/etc/nginx/imscp_roundcube.conf'
    );
    return 1 unless defined( my $fileC = $file->getAsRef());

    ${ $fileC } = process( { GUI_ROOT_DIR => $CWD }, ${ $fileC } );

    $file->save();
}

=item _setupSqlUser( )

 Setup SQL user for Roundcube

 Return int 0 on success, other on failure

=cut

sub _setupSqlUser
{
    my ( $self ) = @_;

    local $@;
    eval {
        my $database = ::setupGetQuestion( 'DATABASE_NAME' ) . '_roundcube';
        my $databaseUserHost = ::setupGetQuestion( 'DATABASE_USER_HOST' );
        my $sqlServer = Servers::sqld->factory();

        for my $host (
            $::imscpOldConfig{'DATABASE_USER_HOST'},
            $databaseUserHost
        ) {
            next unless length $host;
            $sqlServer->dropUser( $self->{'_roundcube_sql_user'}, $host );
        }

        $sqlServer->createUser(
            $self->{'_roundcube_sql_user'},
            $databaseUserHost,
            $self->{'_roundcube_control_user_passwd'}
        );

        # Grant 'all' privileges on the iMSCP Roundcube database
        $self->{'dbh'}->do(
            "
                GRANT ALL PRIVILEGES ON `@{ [ $database =~ s/([%_])/\\$1/gr ] }`.*
                TO ?\@?
            ",
            undef,
            $self->{'_roundcube_sql_user'},
            $databaseUserHost
        );

        # Grant 'select' privileges on both mail_addr and mail_pass columns of
        # the <imscp>.mail_users database table.
        # Grant 'update' privileges on the mail_pass columns of the
        # <imscp>.mail_users database table (Roundcube password plugin).
        # No need to escape wildcard characters.
        # See https://bugs.mysql.com/bug.php?id=18660
        $self->{'dbh'}->do(
            "
                GRANT SELECT (`mail_addr`, `mail_pass`), UPDATE (`mail_pass`)
                ON `@{ [ ::setupGetQuestion( 'DATABASE_NAME' ) ] }`.`mail_users`
                TO ?\@?
            ",
            undef,
            $self->{'_roundcube_sql_user'},
            $databaseUserHost
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _setupDatabase( )

 Setup datbase for Roundcube

 Return int 0 on success, other on failure

=cut

sub _setupDatabase
{
    my ( $self ) = @_;

    my $appDir = "$CWD/vendor/imscp/roundcube/roundcubemail";

    local $@;
    my $rs = eval {
        my $database = ::setupGetQuestion( 'DATABASE_NAME' ) . '_roundcube';

        if ( !$self->{'dbh'}->selectrow_hashref(
            'SHOW DATABASES LIKE ?', undef, $database
        ) || !$self->{'dbh'}->selectrow_hashref(
            "SHOW TABLES FROM `$database`"
        ) ) {
            $self->{'dbh'}->do(
                "
                    CREATE DATABASE IF NOT EXISTS `$database`
                    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
                "
            );

            # Create Roundcube database schema
            my $rs = execute(
                $self->_getSuCmd(
                    '/usr/bin/php', "$appDir/bin/initdb.sh",
                    '--dir', "$appDir/SQL"
                ),
                \my $stdout,
                \my $stderr
            );
            debug( $stdout ) if length $stdout;
            error( $stderr || $stdout || 'Unknown error' ) if $rs;
            return $rs;
        }

        # Update Roundcube database schema
        my $rs = execute(
            $self->_getSuCmd(
                '/usr/bin/php', "$appDir/bin/updatedb.sh",
                '--dir', "$appDir/SQL",
                '--package', 'roundcube'
            ),
            \my $stdout,
            \my $stderr
        );
        debug( $stdout ) if length $stdout;
        error( $stderr || $stdout || 'Unknown error' ) if $rs;
        return $rs if $rs;

        # Ensure tha `users`.`mail_host` entries are set with expected hostname
        my $hostname = 'localhost';
        $self->{'events'}->trigger(
            'beforeUpdateRoundCubeMailHostEntries', \$hostname
        );

        $self->{'dbh'}->do(
            "
                UPDATE IGNORE `$database`.`users`
                SET `mail_host` = ?
            ",
            undef,
            $hostname
        );
        $self->{'dbh'}->do(
            "
                DELETE FROM `$database`.`users`
                WHERE `mail_host` <> ?
            ",
            undef,
            $hostname
        );

        0;
    };
    if ( $@ ) {
        error( $@ );
        $rs = 1;
    }

    $rs;
}

=item _getSuCmd( @_ )

 Return SU command

 Param list @_ Command
 Return array command

=cut

sub _getSuCmd
{
    shift;

    [
        '/bin/su',
        '-l', $::imscpConfig{'SYSTEM_USER_PREFIX'}
            . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
        '-s', '/bin/sh',
        '-c', "@_"
    ];
}

=back

=head1 AUTHOR

 Laurent Declercq <l.declercq@nuxwin.com>

=cut

1;
__END__
