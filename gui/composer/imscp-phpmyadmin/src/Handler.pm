=head1 NAME

 Package::SqlAdminTools::PhpMyAdmin::Handler - i-MSCP PhpMyAdmin package handler

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

package Package::SqlAdminTools::PhpMyAdmin::Handler;

use strict;
use warnings;
use Digest::SHA;
use File::Basename 'basename';
use File::Spec;
use File::Temp;
use iMSCP::Boolean;
use iMSCP::Crypt qw/ decryptRijndaelCBC encryptRijndaelCBC randomStr /;
use iMSCP::Cwd '$CWD';
use iMSCP::Database;
use iMSCP::Debug qw/ debug error /;
use iMSCP::Dir;
use iMSCP::EventManager;
use iMSCP::Execute qw/ execute escapeShell /;
use iMSCP::File;
use iMSCP::Rights 'setRights';
use iMSCP::TemplateParser qw/ getBloc replaceBloc process /;
use LWP::UserAgent;
use Scalar::Defer 'lazy';
use Servers::sqld;
use parent 'Common::Object';

=head1 DESCRIPTION

 i-MSCP PhpMyAdmin package handler.

 The phpMyAdmin application is not shipped with this package. The pinned
 upstream release (see %UPSTREAM below) is downloaded from
 https://files.phpmyadmin.net/ at setup time, verified against the pinned
 SHA-256 checksum and extracted into the
 <GUI_ROOT_DIR>/vendor/imscp/phpmyadmin/phpmyadmin directory.

 The release tarball ships with all PHP dependencies and compiled assets.

=cut

# Pinned upstream release. phpMyAdmin 5.2.x requires PHP >= 7.2.5.
# Checksum is the one published at <url>.sha256; release tarball signature
# verified with the phpMyAdmin release key
# (3D06A59ECE730EB71B511C17CE752F178259BD92).
my %UPSTREAM = (
    version => '5.2.3',
    url     => 'https://files.phpmyadmin.net/phpMyAdmin/5.2.3/phpMyAdmin-5.2.3-all-languages.tar.gz',
    sha256  => '12ba1c425fa4071abbd4e7668c9ebdeac0b0755a467a6d6d5026122bb47c102b'
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

    my $rs = $self->_installUpstream();
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
        iMSCP::Dir->new( dirname => "$CWD/data/tmp/phpmyadmin" )->make( {
            user  => $::imscpConfig{'SYSTEM_USER_PREFIX'}
                . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
            group => $::imscpConfig{'SYSTEM_USER_PREFIX'}
                . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
            mode  => 0750
        } );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    my $rs = $self->_buildConfigFiles();
    $rs ||= $self->_buildHttpdConfigFile();
    $rs ||= $self->_setupDatabase();
    $rs ||= $self->_setupSqlUser();
}

=item postinstall( )

 Post-installation tasks

 Return int 0 on success, other on failure

=cut

sub postinstall
{
    local $CWD = $::imscpConfig{'GUI_ROOT_DIR'};

    if ( -l "$CWD/public/tools/phpmyadmin" ) {
        my $rs = iMSCP::File->new(
            filename => "$CWD/public/tools/phpmyadmin"
        )->delFile();
        return $rs if $rs;
    }

    unless ( symlink( File::Spec->abs2rel(
        "$CWD/vendor/imscp/phpmyadmin/phpmyadmin", "$CWD/public/tools"
    ),
        "$CWD/public/tools/phpmyadmin"
    ) ) {
        error( sprintf(
            "Couldn't create symlink for the PhpMyAdmin SQL administration tool: %s",
            $!
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

    if ( -l "$CWD/public/tools/phpmyadmin" ) {
        my $rs = iMSCP::File->new(
            filename => "$CWD/public/tools/phpmyadmin"
        )->delFile();
        return $rs if $rs;
    }

    if ( -f '/etc/nginx/imscp_pma.conf' ) {
        my $rs = iMSCP::File->new(
            filename => '/etc/nginx/imscp_pma.conf'
        )->delFile();
        return $rs if $rs;
    }

    local $@;
    eval {
        iMSCP::Dir->new( dirname => "$CWD/vendor/imscp/phpmyadmin/phpmyadmin" )->remove();
        iMSCP::Dir->new( dirname => "$CWD/data/tmp/phpmyadmin" )->remove();
        iMSCP::Dir->new( dirname => $self->_getCacheDir())->remove();

        $self->{'dbh'}->do(
            "DROP DATABASE IF EXISTS `@{ [ $::imscpConfig{'DATABASE_NAME'} . '_pma' ] }`"
        );

        my ( $controlUser ) = @{ $self->{'dbh'}->selectcol_arrayref(
            "SELECT `value` FROM `config` WHERE `name` = 'PMA_CONTROL_USER'"
        ) };

        if ( defined $controlUser ) {
            $controlUser = decryptRijndaelCBC(
                $::imscpDBKey, $::imscpDBiv, $controlUser
            );

            for my $host (
                $::imscpOldConfig{'DATABASE_USER_HOST'},
                $::imscpConfig{'DATABASE_USER_HOST'}
            ) {
                next unless length $host;
                Servers::sqld->factory()->dropUser( $controlUser, $host );
            }
        }

        $self->{'dbh'}->do( "DELETE FROM `config` WHERE `name` LIKE 'PMA_%'" );
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

 Event listener that injects Httpd configuration for PhpMyAdmin into the i-MSCP
 control panel Nginx vhost files

 Return int 0 on success, other on failure

=cut

sub afterFrontEndBuildConfFile
{
    my ( $tplContent, $tplName ) = @_;

    return 0 unless grep ( $_ eq $tplName, qw/
        00_master.nginx 00_master_ssl.nginx
    / );

    ${ $tplContent } = replaceBloc(
        "# SECTION custom BEGIN.\n",
        "# SECTION custom END.\n",
        "    # SECTION custom BEGIN.\n"
            . getBloc(
                "# SECTION custom BEGIN.\n",
                "# SECTION custom END.\n",
                ${ $tplContent }
            )
            . "    include imscp_pma.conf;\n"
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

 Return Package::SqlAdminTools::PhpMyAdmin::Handler

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
    "$::imscpConfig{'GUI_ROOT_DIR'}/data/persistent/addons/phpmyadmin";
}

=item _installUpstream( )

 Download, verify and install the pinned upstream phpMyAdmin release into the
 <GUI_ROOT_DIR>/vendor/imscp/phpmyadmin/phpmyadmin directory

 The installation is skipped if the expected release is already installed.

 Return int 0 on success, other on failure

=cut

sub _installUpstream
{
    my ( $self ) = @_;

    my $pkgDir = "$::imscpConfig{'GUI_ROOT_DIR'}/vendor/imscp/phpmyadmin";
    my $appDir = "$pkgDir/phpmyadmin";
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
                'phpMyAdmin %s is already installed. Skipping download.',
                $UPSTREAM{'version'}
            ));
            return 0;
        }
    }

    local $@;
    eval {
        -d $pkgDir or die( sprintf(
            "The %s directory doesn't exist. The imscp/phpmyadmin composer package is not installed.",
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
                    "Couldn't download the phpMyAdmin %s release archive from %s: %s",
                    $UPSTREAM{'version'}, $UPSTREAM{'url'}, $response->status_line
                ));
            }

            my $sha256 = _sha256( "$archive.part" );
            unless ( $sha256 eq $UPSTREAM{'sha256'} ) {
                unlink( "$archive.part" );
                die( sprintf(
                    "Checksum mismatch for the phpMyAdmin %s release archive (expected SHA-256: %s, got: %s)",
                    $UPSTREAM{'version'}, $UPSTREAM{'sha256'}, $sha256
                ));
            }

            rename( "$archive.part", $archive ) or die( sprintf(
                "Couldn't rename %s.part to %s: %s", $archive, $archive, $!
            ));
        }

        # Extract the archive into a staging directory
        my $newDir = "$pkgDir/.phpmyadmin.new";
        my $oldDir = "$pkgDir/.phpmyadmin.old";
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
            "Couldn't extract the phpMyAdmin %s release archive: %s",
            $UPSTREAM{'version'}, $stderr || 'Unknown error'
        ));

        -f "$newDir/index.php" && -f "$newDir/sql/create_tables.sql" && -d "$newDir/vendor" or die(
            "Unexpected phpMyAdmin release archive layout."
        );

        # The setup script is not needed (configuration is generated by i-MSCP)
        iMSCP::Dir->new( dirname => "$newDir/setup" )->remove();

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

 Build PhpMyadminConfiguration files

 Return int 0 on success, other on failure

=cut

sub _buildConfigFiles
{
    my ( $self ) = @_;

    local $@;
    my $rs = eval {
        # Main configuration file
        my %config = @{ $self->{'dbh'}->selectcol_arrayref(
            "SELECT `name`, `value` FROM `config` WHERE `name` LIKE 'PMA_%'",
            { Columns => [ 1, 2 ] }
        ) };

        ( $config{'PMA_BLOWFISH_SECRET'} = decryptRijndaelCBC(
            $::imscpDBKey, $::imscpDBiv, $config{'PMA_BLOWFISH_SECRET'} // ''
        ) || randomStr( 32, iMSCP::Crypt::ALNUM ) );

        # As of phpMyAdmin 5.2, the secret must be exactly 32 bytes long
        $config{'PMA_BLOWFISH_SECRET'} = randomStr( 32, iMSCP::Crypt::ALNUM )
            unless length $config{'PMA_BLOWFISH_SECRET'} == 32
            && $config{'PMA_BLOWFISH_SECRET'} !~ /['\\]/;

        ( $config{'PMA_CONTROL_USER'} = decryptRijndaelCBC(
            $::imscpDBKey, $::imscpDBiv, $config{'PMA_CONTROL_USER'} // ''
        ) || 'pma_' . randomStr( 12, iMSCP::Crypt::ALNUM ) );

        ( $config{'PMA_CONTROL_USER_PASSWD'} = decryptRijndaelCBC(
            $::imscpDBKey,
            $::imscpDBiv,
            $config{'PMA_CONTROL_USER_PASSWD'} // ''
        ) || randomStr( 16, iMSCP::Crypt::ALNUM ) );

        (
            $self->{'_pma_control_user'},
            $self->{'_pma_control_user_passwd'}
        ) = (
            $config{'PMA_CONTROL_USER'}, $config{'PMA_CONTROL_USER_PASSWD'}
        );

        # Save generated values in database (encrypted)
        $self->{'dbh'}->do(
            '
                INSERT INTO `config` (`name`,`value`)
                VALUES (?,?),(?,?),(?,?)
                ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)
            ',
            undef,
            'PMA_BLOWFISH_SECRET',
            encryptRijndaelCBC(
                $::imscpDBKey, $::imscpDBiv, $config{'PMA_BLOWFISH_SECRET'}
            ),
            'PMA_CONTROL_USER',
            encryptRijndaelCBC(
                $::imscpDBKey, $::imscpDBiv, $config{'PMA_CONTROL_USER'}
            ),
            'PMA_CONTROL_USER_PASSWD',
            encryptRijndaelCBC(
                $::imscpDBKey, $::imscpDBiv, $config{'PMA_CONTROL_USER_PASSWD'}
            )
        );

        my $data = {
            BLOWFISH_SECRET   => $config{'PMA_BLOWFISH_SECRET'},
            DATABASE_HOSTNAME => ::setupGetQuestion( 'DATABASE_HOST' ),
            DATABASE_PORT     => ::setupGetQuestion( 'DATABASE_PORT' ),
            DATABASE_NAME     => ::setupGetQuestion( 'DATABASE_NAME' ) . '_pma',
            DATABASE_USER     => $config{'PMA_CONTROL_USER'} =~ s/(['\\])/\\$1/gr,
            DATABASE_PASSWORD => $config{'PMA_CONTROL_USER_PASSWD'} =~ s/(['\\])/\\$1/gr,
            SESSION_SAVE_PATH => "$CWD/data/sessions/",
            TMP_DIR           => "$CWD/data/tmp/phpmyadmin/"
        };

        my $rs = $self->{'events'}->trigger(
            'onLoadTemplate',
            'phpmyadmin',
            'config.inc.php',
            \my $cfgTpl,
            $data
        );
        return $rs if $rs;

        unless ( defined $cfgTpl ) {
            $cfgTpl = iMSCP::File->new(
                filename => "$CWD/vendor/imscp/phpmyadmin/src/config.inc.php"
            )->get();
            return 1 unless defined $cfgTpl;
        }

        $cfgTpl = process( $data, $cfgTpl );

        my $file = iMSCP::File->new(
            filename => "$CWD/vendor/imscp/phpmyadmin/phpmyadmin/config.inc.php"
        );
        $file->set( $cfgTpl );
        $rs = $file->save();
        $rs ||= $file->owner(
            $::imscpConfig{'SYSTEM_USER_PREFIX'} . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
            $::imscpConfig{'SYSTEM_USER_PREFIX'} . $::imscpConfig{'SYSTEM_USER_MIN_UID'}
        );
        $rs ||= $file->mode( 0640 );
    };
    if ( $@ ) {
        error( $@ );
        $rs = 1;
    }

    $rs;
}

=item _buildHttpdConfigFile( )

 Build httpd configuration file for PhpMyAdmin

 Return int 0 on success, other on failure

=cut

sub _buildHttpdConfigFile
{
    my $rs = iMSCP::File->new(
        filename => "$CWD/vendor/imscp/phpmyadmin/src/nginx.conf"
    )->copyFile( '/etc/nginx/imscp_pma.conf' );
    return $rs if $rs;

    my $file = iMSCP::File->new( filename => '/etc/nginx/imscp_pma.conf' );
    return 1 unless defined( my $fileC = $file->getAsRef());

    ${ $fileC } = process( { GUI_ROOT_DIR => $CWD }, ${ $fileC } );

    $file->save();
}

=item _setupDatabase( )

 Setup database (phpMyAdmin configuration storage) for PhpMyAdmin

 The create_tables.sql script only makes use of 'CREATE ... IF NOT EXISTS'
 statements, hence existing data (bookmarks, user preferences...) are kept.

 Return int 0 on success, other on failure

=cut

sub _setupDatabase
{
    my ( $self ) = @_;

    my $database = ::setupGetQuestion( 'DATABASE_NAME' ) . '_pma';

    my $file = iMSCP::File->new(
        filename => "$CWD/vendor/imscp/phpmyadmin/phpmyadmin/sql/create_tables.sql"
    );
    return 1 unless defined( my $fileC = $file->getAsRef());

    ${ $fileC } =~ s/\bphpmyadmin\b/$database/gm;

    my $schemaFile = File::Temp->new();
    print $schemaFile ${ $fileC };
    $schemaFile->close();

    # As of MariaDB 11.0, the mysql* program names are deprecated
    # compatibility symlinks that print a warning on STDERR.
    my $rs = execute(
        ( -x '/usr/bin/mariadb' ? '/usr/bin/mariadb' : '/usr/bin/mysql' )
            . ' < ' . escapeShell( $schemaFile->filename()),
        \my $stdout,
        \my $stderr
    );
    debug( $stdout ) if length $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $rs;
}

=item _setupSqlUser( )

 Setup SQL user for PhpMyAdmin

 Return int 0 on success, other on failure

=cut

sub _setupSqlUser
{
    my ( $self ) = @_;

    local $@;
    eval {
        my $database = ::setupGetQuestion( 'DATABASE_NAME' ) . '_pma';
        my $databaseUserHost = ::setupGetQuestion( 'DATABASE_USER_HOST' );
        my $sqlServer = Servers::sqld->factory();

        for my $host (
            $::imscpOldConfig{'DATABASE_USER_HOST'},
            $databaseUserHost
        ) {
            next unless length $host;
            $sqlServer->dropUser( $self->{'_pma_control_user'}, $host );
        }

        $sqlServer->createUser(
            $self->{'_pma_control_user'},
            $databaseUserHost,
            $self->{'_pma_control_user_passwd'}
        );

        # Control user privileges
        # See https://docs.phpmyadmin.net/en/latest/setup.html#controluser
        # As of MariaDB 10.4, mysql.user is a view; SELECT is granted on the
        # whole view.
        for my $table ( qw/ user db / ) {
            $self->{'dbh'}->do(
                "GRANT SELECT ON `mysql`.`$table` TO ?\@?",
                undef,
                $self->{'_pma_control_user'},
                $databaseUserHost
            );
        }

        # Check for mysql.host table existence (as for MySQL >= 5.6.7, the
        # mysql.host table is no longer provided)
        if ( $self->{'dbh'}->selectrow_hashref(
            "SHOW tables FROM `mysql` LIKE 'host'"
        ) ) {
            $self->{'dbh'}->do(
                'GRANT SELECT ON `mysql`.`host` TO ?@?',
                undef,
                $self->{'_pma_control_user'},
                $databaseUserHost
            );
        }

        $self->{'dbh'}->do(
            '
                GRANT SELECT (
                    `Host`,`Db`,`User`,`Table_name`,`Table_priv`,`Column_priv`
                ) ON `mysql`.`tables_priv`
                TO ?@?
            ',
            undef,
            $self->{'_pma_control_user'},
            $databaseUserHost
        );

        $self->{'dbh'}->do(
            "
                GRANT SELECT,INSERT,UPDATE,DELETE
                ON `@{ [ $database =~ s/([%_])/\\$1/gr ] }`.*
                TO ?\@?
            ",
            undef,
            $self->{'_pma_control_user'},
            $databaseUserHost
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=back

=head1 AUTHOR

 Laurent Declercq <l.declercq@nuxwin.com>

=cut

1;
__END__
