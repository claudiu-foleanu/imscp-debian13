=head1 NAME

 Package::WebFtpClients::ElFinder::Handler - i-MSCP elFinder package handler

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

package Package::WebFtpClients::ElFinder::Handler;

use strict;
use warnings;
use Cwd ();
use Digest::SHA;
use Errno 'EEXIST';
use Fcntl qw/
    O_CREAT O_EXCL O_NOFOLLOW O_NONBLOCK O_RDONLY O_WRONLY S_ISGID S_ISUID S_ISVTX
/;
use File::Basename qw/ basename dirname /;
use File::Copy ();
use File::Find ();
use File::Spec;
use File::Temp;
use iMSCP::Boolean;
use iMSCP::Crypt 'randomStr';
use iMSCP::Cwd '$CWD';
use iMSCP::Debug qw/ debug error /;
use iMSCP::Dir;
use iMSCP::EventManager;
use iMSCP::Execute 'execute';
use iMSCP::File;
use iMSCP::Rights 'setRights';
use iMSCP::TemplateParser qw/ getBloc replaceBloc process /;
use LWP::UserAgent;
use POSIX ();
use parent 'Common::Object';

=head1 DESCRIPTION

 i-MSCP elFinder package handler.

 Provides a Web-based file manager for customers. Customers log in with their
 FTP account credentials and all file operations are made through the local
 FTP server (elFinder FTP volume driver), hence ownership, chroot and quotas
 enforced by the FTP server apply.

 The elFinder application is not shipped with this package. The pinned
 upstream release (see %UPSTREAM below) is downloaded from GitHub at setup
 time, verified against the pinned SHA-256 checksum and extracted into the
 <GUI_ROOT_DIR>/vendor/imscp/elfinder/elfinder directory, along with the
 jQuery and jQuery UI libraries (see @ASSETS below).

 Layout:
  vendor/imscp/elfinder/public   : Document root (front controllers, assets)
  vendor/imscp/elfinder/public/ui: Symlinks to the upstream static assets
  vendor/imscp/elfinder/library  : Front-end library (not reachable)
  vendor/imscp/elfinder/elfinder : Upstream elFinder (not reachable)
  vendor/imscp/elfinder/config.php: Generated configuration file
  data/tmp/elfinder              : Sessions, transfers, rate limiting data

 The control panel directory tree is owned by the control panel user. Any
 operation made in that tree is made with the privileges of that user (see
 _runAsPanelUser()).

=cut

# Pinned upstream release (elFinder 2.1.70 fixes CVE-2026-81889,
# CVE-2026-81890 and CVE-2026-81891). Checksum of the GitHub tag archive.
my %UPSTREAM = (
    version => '2.1.70',
    url     => 'https://github.com/Studio-42/elFinder/archive/refs/tags/2.1.70.tar.gz',
    file    => 'elFinder-2.1.70.tar.gz',
    sha256  => 'd4cf81a4e3f3216db00a3d6c5c0baa1c8cc4e14411344fe6762a2954a01ba33a'
);

# Client-side libraries required by elFinder (served locally, no CDN).
# Checksums match the SRI hashes published at https://releases.jquery.com/
my $JQUI = 'https://code.jquery.com/ui/1.14.2';
my @ASSETS = (
    [
        'https://code.jquery.com/jquery-4.0.0.min.js',
        'jquery/jquery.min.js',
        '39a546ea9ad97f8bfaf5d3e0e8f8556adb415e470e59007ada9759dce472adaa'
    ],
    [
        "$JQUI/jquery-ui.min.js",
        'jquery/jquery-ui.min.js',
        '99b95259f6d8cdaabf7fee1a93232113a5c42c2a2ee236e480fbfe2503c44763'
    ],
    [
        "$JQUI/themes/smoothness/jquery-ui.min.css",
        'jquery/jquery-ui.min.css',
        'e8e8c54ec24df876472993e56099fe1970dd2a8d084b934da13f28a05b3460d7'
    ],
    map {
        [ "$JQUI/themes/smoothness/images/$_->[0]", "jquery/images/$_->[0]", $_->[1] ]
    } (
        [ 'ui-bg_glass_55_fbf9ee_1x400.png', '0814ea0961f8c49840f32c365de26ded7eddd45fa3433ff12399eca29592d802' ],
        [ 'ui-bg_glass_65_ffffff_1x400.png', '72e119acfc9cd8a9f58faf672162ff6366c97ae4061a3f3e98975444e53c864a' ],
        [ 'ui-bg_glass_75_dadada_1x400.png', '9815bc135f3af817ee5deb0e5e1e32440ee0c03a7bd04b943c9d28da7684d776' ],
        [ 'ui-bg_glass_75_e6e6e6_1x400.png', '23fe2d2471a0fc27dca0cbd31c6c49a6f15b25c9b9f06070c72fcb9c187a95bc' ],
        [ 'ui-bg_glass_95_fef1ec_1x400.png', 'b5d4373edea97660d71641f9fa41963c9554f9fd10bed329b686c1ef2db8e93d' ],
        [ 'ui-bg_highlight-soft_75_cccccc_1x100.png', 'b593a05e716ddd1dc1705c4584cee466b2c98d2ae70828291a225b5aafcf3388' ],
        [ 'ui-icons_222222_256x240.png', 'a23507318456f644a28c18084dc575be40bec9b274c81e41bd5c11e173ea1634' ],
        [ 'ui-icons_2e83ff_256x240.png', 'f032b4e0e3b8e85bf21cf7326d7cc112989cd5266a8f4b94cd639211d9c0c81e' ],
        [ 'ui-icons_454545_256x240.png', '8f06f19637eb1b2dae0bcb8ac9402088dc6a85cd333087abc9be580f8752f6b9' ],
        [ 'ui-icons_888888_256x240.png', '14ee34c7c8175a46625780531f1bec8cea6125a9fa828f6515c023839a3c62b8' ],
        [ 'ui-icons_cd0a0a_256x240.png', 'a2dafcc85530599922b5896691ff429c7f6649a10cf7390cccf7839a0a0c95bc' ]
    )
);

# Upstream directories exposed through the public/ui directory
my @UI_DIRS = qw/ css img js sounds jquery /;

# Nginx configuration snippet (included in the control panel vhost files).
# Embedded on purpose: the package directory is writable by the control panel
# user and this file is installed as root in the Nginx configuration
# directory.
my $NGINX_CONF = <<'EOF';
# elFinder file manager - auto-generated by i-MSCP
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN

location = /elfinder {
    return 301 /elfinder/;
}

location ^~ /elfinder/ {
    # {GUI_ROOT_DIR}/public/tools/elfinder is a symlink to the public
    # directory of the i-MSCP elFinder package. The upstream elFinder sources
    # and the front-end library live outside of that directory. Only the
    # static assets (ui/ symlinks) are taken from the upstream sources.
    root {GUI_ROOT_DIR}/public/tools;
    index index.php;

    # Deny access to hidden files
    location ~ /\. {
        return 404;
    }

    # Front controllers (login page/file manager and elFinder connector)
    location ~ ^/elfinder/(?:index|connector)\.php$ {
        include imscp_fastcgi.conf;
    }

    # Static assets
    location ~ ^/elfinder/(?:assets|ui/(?:css|img|js|sounds|jquery))/[^/].*\.(?:css|js|png|gif|jpe?g|svg|ico|woff2?|ttf|eot|mp3|wav|ogg|json)$ {
        add_header X-Content-Type-Options nosniff;
        expires 7d;
    }

    # Anything else is not reachable
    location ~ ^/elfinder/. {
        return 404;
    }
}
EOF

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
        my $guiDir = $::imscpConfig{'GUI_ROOT_DIR'};
        _runAsPanelUser( sub {
            iMSCP::Dir->new( dirname => "$guiDir/data/tmp/elfinder" )->make( {
                mode => 0750
            } );
        } );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    my $rs = $self->_buildConfigFile();
    $rs ||= $self->_buildHttpdConfigFile();
}

=item postinstall( )

 Post-installation tasks

 Return int 0 on success, other on failure

=cut

sub postinstall
{
    my ( $self ) = @_;

    my $guiDir = $::imscpConfig{'GUI_ROOT_DIR'};
    my $pkgDir = "$guiDir/vendor/imscp/elfinder";

    local $@;
    eval {
        _runAsPanelUser( sub {
            # Symlinks to the upstream static assets
            iMSCP::Dir->new( dirname => "$pkgDir/public/ui" )->remove();
            iMSCP::Dir->new( dirname => "$pkgDir/public/ui" )->make( {
                mode => 0750
            } );

            for my $dir ( @UI_DIRS ) {
                -d "$pkgDir/elfinder/$dir" or die( sprintf(
                    "The %s directory doesn't exist.", "$pkgDir/elfinder/$dir"
                ));
                symlink( "../../elfinder/$dir", "$pkgDir/public/ui/$dir" ) or die(
                    sprintf(
                        "Couldn't create symlink for the %s directory: %s",
                        "$pkgDir/elfinder/$dir", $!
                    )
                );
            }

            # Tool symlink
            if ( -l "$guiDir/public/tools/elfinder" ) {
                unlink( "$guiDir/public/tools/elfinder" ) or die( sprintf(
                    "Couldn't remove the %s symlink: %s",
                    "$guiDir/public/tools/elfinder", $!
                ));
            }

            symlink(
                File::Spec->abs2rel( "$pkgDir/public", "$guiDir/public/tools" ),
                "$guiDir/public/tools/elfinder"
            ) or die( sprintf(
                "Couldn't create symlink for the elFinder file manager: %s", $!
            ));
        } );
    };
    if ( $@ ) {
        error( $@ );
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

    if ( -l "$CWD/public/tools/elfinder" ) {
        my $rs = iMSCP::File->new(
            filename => "$CWD/public/tools/elfinder"
        )->delFile();
        return $rs if $rs;
    }

    if ( -f '/etc/nginx/imscp_elfinder.conf' ) {
        my $rs = iMSCP::File->new(
            filename => '/etc/nginx/imscp_elfinder.conf'
        )->delFile();
        return $rs if $rs;
    }

    if ( -f "$CWD/vendor/imscp/elfinder/config.php" ) {
        my $rs = iMSCP::File->new(
            filename => "$CWD/vendor/imscp/elfinder/config.php"
        )->delFile();
        return $rs if $rs;
    }

    local $@;
    eval {
        _removeDirAsPanelUser(
            "$CWD/vendor/imscp/elfinder/public/ui",
            "$CWD/vendor/imscp/elfinder/elfinder",
            "$CWD/data/tmp/elfinder",
            $self->_getCacheDir()
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

 Event listener that injects Httpd configuration for elFinder into the i-MSCP
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
            . "    include imscp_elfinder.conf;\n"
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

 Return Package::WebFtpClients::ElFinder::Handler

=cut

sub _init
{
    my ( $self ) = @_;

    $self->{'events'} = iMSCP::EventManager->getInstance();
    $self;
}

=item _getCacheDir( )

 Get directory in which upstream release archives are cached

 Return string

=cut

sub _getCacheDir
{
    "$::imscpConfig{'GUI_ROOT_DIR'}/data/persistent/addons/elfinder";
}

=item _getStamp( )

 Get stamp identifying the upstream release and assets to install

 Return string

=cut

sub _getStamp
{
    join ' ', $UPSTREAM{'version'}, $UPSTREAM{'sha256'},
        Digest::SHA::sha256_hex( join ',', map { "$_->[1]:$_->[2]" } @ASSETS );
}

=item _installUpstream( )

 Download, verify and install the pinned upstream elFinder release and the
 client-side libraries into the <GUI_ROOT_DIR>/vendor/imscp/elfinder/elfinder
 directory

 The installation is skipped if the expected release is already installed.

 Return int 0 on success, other on failure

=cut

sub _installUpstream
{
    my ( $self ) = @_;

    my $pkgDir = "$::imscpConfig{'GUI_ROOT_DIR'}/vendor/imscp/elfinder";
    my $appDir = "$pkgDir/elfinder";
    my $stamp = _getStamp();

    my $curStamp = eval { _readFile( "$appDir/.imscp-upstream" ) } // '';
    chomp( $curStamp );
    if ( $curStamp eq $stamp && -f "$appDir/php/elFinder.class.php" ) {
        debug( sprintf(
            'elFinder %s is already installed. Skipping download.',
            $UPSTREAM{'version'}
        ));
        return 0;
    }

    local $@;
    eval {
        -d $pkgDir or die( sprintf(
            "The %s directory doesn't exist. The imscp/elfinder composer package is not installed.",
            $pkgDir
        ));

        # Get the verified files into a private (root-owned, 0700) temporary
        # directory. The files are used from there only.
        my $tmpDir = File::Temp->newdir( 'imscp-elfinder-XXXXXX', TMPDIR => TRUE );
        my $cacheDir = $self->_getCacheDir();

        my @files = map {
            my ( $url, $sha256, $name, $dst ) = @{ $_ };
            my ( $file, $fromCache ) = _fetchVerified(
                $url, $sha256, "$cacheDir/$name", $tmpDir->dirname()
            );
            open( my $fh, '<', $file ) or die( sprintf(
                "Couldn't open %s: %s", $file, $!
            ));
            +{ fh => $fh, cacheFile => "$cacheDir/$name", fromCache => $fromCache, dst => $dst };
        } (
            [ $UPSTREAM{'url'}, $UPSTREAM{'sha256'}, $UPSTREAM{'file'}, undef ],
            map { [ $_->[0], $_->[2], $_->[1] =~ s%/%_%gr, $_->[1] ] } @ASSETS
        );

        _checkArchive( "$tmpDir/$UPSTREAM{'file'}" );

        _runAsPanelUser( sub {
            for my $file ( @files ) {
                _storeInCache( $file->{'fh'}, $file->{'cacheFile'} ) unless $file->{'fromCache'};
            }

            # Extract the archive into a staging directory
            my $newDir = "$pkgDir/.elfinder.new";
            my $oldDir = "$pkgDir/.elfinder.old";
            iMSCP::Dir->new( dirname => $_ )->remove() for $newDir, $oldDir;
            iMSCP::Dir->new( dirname => $newDir )->make( { mode => 0750 } );

            _extractArchive( $files[0]->{'fh'}, $newDir );

            -f "$newDir/php/elFinder.class.php"
                && -f "$newDir/php/elFinderVolumeFTP.class.php"
                && -f "$newDir/php/autoload.php"
                && -f "$newDir/js/elfinder.min.js"
                && -f "$newDir/css/elfinder.min.css" or die(
                "Unexpected elFinder release archive layout."
            );

            # Remove files which are not needed (demo pages, demo files
            # directory, connector samples, package manager files)
            iMSCP::Dir->new( dirname => "$newDir/$_" )->remove() for qw(
                files php/.tmp
            );
            for my $file ( qw(
                .gitignore elfinder.html elfinder.legacy.html main.default.js
                bower.json composer.json package.json
                php/connector.minimal.php-dist php/connector.maximal.php-dist
            ) ) {
                next unless -e "$newDir/$file" || -l "$newDir/$file";
                unlink( "$newDir/$file" ) or die( sprintf(
                    "Couldn't remove %s: %s", "$newDir/$file", $!
                ));
            }

            # Client-side libraries
            for my $file ( @files[1 .. $#files] ) {
                iMSCP::Dir->new( dirname => dirname( "$newDir/$file->{'dst'}" ))->make();
                seek( $file->{'fh'}, 0, 0 ) or die( sprintf( "Couldn't seek: %s", $! ));
                binmode( $file->{'fh'} );
                _writeFile(
                    "$newDir/$file->{'dst'}",
                    do { local $/; readline( $file->{'fh'} ) },
                    0640
                );
            }

            _writeFile( "$newDir/.imscp-upstream", "$stamp\n", 0640 );

            setRights( $newDir, {
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
        } );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _buildConfigFile( )

 Build elFinder front-end configuration file

 Return int 0 on success, other on failure

=cut

sub _buildConfigFile
{
    my ( $self ) = @_;

    local $@;
    my $rs = eval {
        my $guiDir = $::imscpConfig{'GUI_ROOT_DIR'};
        my $cfgFile = "$guiDir/vendor/imscp/elfinder/config.php";
        my $newSecretKey = randomStr( 64, '0123456789abcdef' );

        my $data = {
            FTP_SSL         => ::setupGetQuestion( 'SERVICES_SSL_ENABLED' ) eq 'yes'
                ? 'true' : 'false',
            TMP_DIR         => "$guiDir/data/tmp/elfinder",
            SECRET_KEY      => undef,
            UPLOAD_MAX_SIZE => '128M',
            TIMEZONE        => ::setupGetQuestion( 'TIMEZONE' ) || 'UTC'
        };

        my $rs = $self->{'events'}->trigger(
            'onLoadTemplate', 'elfinder', 'config.php', \my $cfgTpl, $data
        );
        return $rs if $rs;

        # Values are put in single-quoted PHP strings
        $data->{$_} =~ s/(['\\])/\\$1/g for qw/ TMP_DIR UPLOAD_MAX_SIZE TIMEZONE /;

        # The existing configuration file and the template are read, and the
        # configuration file written with the privileges of the control panel
        # user
        _runAsPanelUser( sub {
            # Keep the secret key (and therefore the active sessions) if any
            unless ( defined $data->{'SECRET_KEY'} ) {
                my $content = -f $cfgFile ? eval { _readFile( $cfgFile ) } // '' : '';
                ( $data->{'SECRET_KEY'} ) = $content =~ /'secret_key'\s*=>\s*'([0-9a-f]{64})'/;
                $data->{'SECRET_KEY'} //= $newSecretKey;
            }

            $cfgTpl //= _readFile( "$guiDir/vendor/imscp/elfinder/src/config.php" );
            _writeFile( $cfgFile, process( $data, $cfgTpl ), 0640 );
        } );

        0;
    };
    if ( $@ ) {
        error( $@ );
        $rs = 1;
    }

    $rs;
}

=item _buildHttpdConfigFile( )

 Build httpd configuration file for elFinder

 Return int 0 on success, other on failure

=cut

sub _buildHttpdConfigFile
{
    local $@;
    my $guiDir = eval { _checkGuiRootDir() };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    _writeSystemFile(
        '/etc/nginx/imscp_elfinder.conf',
        process( { GUI_ROOT_DIR => $guiDir }, $NGINX_CONF )
    );
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

=item _getPanelUser( )

 Get name, UID and GID of the control panel user

 Return list (name, uid, gid), die on failure

=cut

sub _getPanelUser
{
    my $name = $::imscpConfig{'SYSTEM_USER_PREFIX'}
        . $::imscpConfig{'SYSTEM_USER_MIN_UID'};
    my ( $uid, $gid ) = ( getpwnam( $name ) )[ 2, 3 ];

    # The name is also used in system configuration files (cron, logrotate)
    $name =~ /\A[a-z_][a-z0-9_-]*\z/ && defined $uid && $uid > 0
        && defined $gid && $gid > 0 or die( sprintf(
        "Couldn't resolve the %s control panel user", $name
    ));

    ( $name, $uid, $gid );
}

=item _runAsPanelUser( $code )

 Run the given code in a child process with the privileges of the control
 panel user

 The control panel directory tree is owned by the control panel user. All
 operations in that tree (directory creation, file writes, archive extraction,
 permissions) are made with the privileges of that user, so that symlinks,
 hard links or files planted in that tree can only lead to files that this
 user can already modify.

 Note that the code is run with '/' as current directory (paths must be
 absolute, and the $CWD variable must not be used).

 Param coderef $code Code to run
 Return void, die on failure

=cut

sub _runAsPanelUser
{
    my ( $code ) = @_;

    my ( undef, $uid, $gid ) = _getPanelUser();

    pipe( my $rfh, my $wfh ) or die( sprintf( "Couldn't create pipe: %s", $! ));
    defined( my $pid = fork()) or die( sprintf( "Couldn't fork: %s", $! ));

    unless ( $pid ) {
        close( $rfh );

        local $SIG{'__DIE__'} = 'DEFAULT';
        local $@;
        my $ok = eval {
            # Supplementary groups, then real/effective/saved GID and UID
            $) = "$gid $gid";
            POSIX::setgid( $gid ) or die( sprintf( "Couldn't set GID: %s", $! ));
            POSIX::setuid( $uid ) or die( sprintf( "Couldn't set UID: %s", $! ));
            $< == $uid && $> == $uid && "$)" eq "$gid $gid"
                && ( split /\s+/, $( )[0] == $gid or die(
                "Couldn't drop privileges"
            );

            umask( 027 );
            # Temporary files (e.g. command output capture) in the default
            # location, not in a private directory of the caller
            delete $ENV{'TMPDIR'};
            chdir( '/' ) or die( sprintf( "Couldn't change directory: %s", $! ));
            $code->();
            1;
        };
        print { $wfh } ( $@ || 'Unknown error' ) unless $ok;
        close( $wfh );
        # Do not run END blocks nor destructors (DBI handles, temporary files)
        POSIX::_exit( $ok ? 0 : 1 );
    }

    close( $wfh );
    my $error = do { local $/; <$rfh> } // '';
    close( $rfh );
    waitpid( $pid, 0 ) == $pid or die( sprintf(
        "Couldn't wait for child process: %s", $!
    ));
    $? == 0 or die( length $error ? $error : sprintf(
        'Child process failed with status %d', $? >> 8
    ));
}

=item _readFile( $path )

 Read the given regular file (symlinks and special files are refused)

 Param string $path File path
 Return string File content, die on failure

=cut

sub _readFile
{
    my ( $path ) = @_;

    sysopen( my $fh, $path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK ) or die(
        sprintf( "Couldn't open %s for reading: %s", $path, $! )
    );
    -f $fh or die( sprintf( "Refusing to read %s: not a regular file", $path ));
    binmode( $fh );
    my $content = do { local $/; <$fh> } // '';
    close( $fh );
    $content;
}

=item _writeFile( $path, $content, $mode [, $uid, $gid ] )

 Write the given file atomically

 The content is written into a new temporary file, created in the same
 directory with O_CREAT|O_EXCL|O_NOFOLLOW, which is then renamed to the
 target. An existing target is never opened, hence never followed if it is a
 symlink; anything else than a regular file is refused.

 Param string $path File path
 Param string $content File content
 Param int $mode File mode
 Param int $uid OPTIONAL File owner UID
 Param int $gid OPTIONAL File owner GID
 Return void, die on failure

=cut

sub _writeFile
{
    my ( $path, $content, $mode, $uid, $gid ) = @_;

    my ( $dir, $name ) = ( dirname( $path ), basename( $path ));

    if ( lstat( $path ) ) {
        !-l _ && -f _ or die( sprintf(
            "Refusing to write %s: not a regular file", $path
        ));
    }

    my ( $fh, $tmp );
    for my $try ( 1 .. 10 ) {
        $tmp = sprintf( '%s/.%s.%d%09d', $dir, $name, $$, int( rand( 1e9 )));
        last if sysopen( $fh, $tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600 );
        $! == EEXIST && $try < 10 or die( sprintf(
            "Couldn't create %s: %s", $tmp, $!
        ));
    }

    local $@;
    eval {
        binmode( $fh );
        ( print { $fh } $content ) or die( sprintf(
            "Couldn't write %s: %s", $tmp, $!
        ));
        if ( defined $uid ) {
            chown( $uid, $gid, $fh ) or die( sprintf(
                "Couldn't set ownership on %s: %s", $tmp, $!
            ));
        }
        chmod( $mode, $fh ) or die( sprintf(
            "Couldn't set permissions on %s: %s", $tmp, $!
        ));
        close( $fh ) or die( sprintf( "Couldn't close %s: %s", $tmp, $! ));
        rename( $tmp, $path ) or die( sprintf(
            "Couldn't rename %s to %s: %s", $tmp, $path, $!
        ));
        1;
    } or do {
        my $error = $@;
        unlink( $tmp );
        die( $error );
    };
}

=item _writeSystemFile( $path, $content )

 Write the given system configuration file (root:root 0644)

 Param string $path File path
 Param string $content File content
 Return int 0 on success, other on failure

=cut

sub _writeSystemFile
{
    my ( $path, $content ) = @_;

    local $@;
    eval { _writeFile( $path, $content, 0644, 0, 0 ); };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _checkGuiRootDir( )

 Check the GUI root directory path before using it in system configuration
 files

 Return string GUI root directory path, die if the path is not safe

=cut

sub _checkGuiRootDir
{
    my $dir = $::imscpConfig{'GUI_ROOT_DIR'} // '';

    $dir =~ m%\A(?:/[A-Za-z0-9_.-]+)+\z% && $dir !~ m%/\.\.?(?:/|\z)% or die(
        sprintf( 'Unexpected GUI root directory path: %s', $dir )
    );

    $dir;
}

=item _fetchVerified( $url, $sha256, $cacheFile, $tmpDir )

 Get the given file into the given private temporary directory and verify its
 SHA-256 checksum

 The cache directory is writable by the control panel user. A cached file is
 therefore never used in place: it is copied into the private temporary
 directory (root-owned, mode 0700), and only that copy is verified and used
 afterwards. If there is no (valid) cached file, the file is downloaded into
 the private temporary directory.

 Param string $url URL
 Param string $sha256 Expected SHA-256 checksum
 Param string $cacheFile Path of cached file
 Param string $tmpDir Private temporary directory
 Return list Path to the verified file and whether it came from the cache, die on failure

=cut

sub _fetchVerified
{
    my ( $url, $sha256, $cacheFile, $tmpDir ) = @_;

    my $file = "$tmpDir/" . basename( $cacheFile );

    if ( sysopen( my $in, $cacheFile, O_RDONLY | O_NOFOLLOW | O_NONBLOCK ) ) {
        if ( -f $in ) {
            sysopen( my $out, $file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600 ) or die(
                sprintf( "Couldn't create %s: %s", $file, $! )
            );
            File::Copy::copy( $in, $out ) or die( sprintf(
                "Couldn't copy %s to %s: %s", $cacheFile, $file, $!
            ));
            close( $out ) or die( sprintf( "Couldn't close %s: %s", $file, $! ));
            close( $in );

            return ( $file, TRUE ) if _sha256( $file ) eq $sha256;

            debug( sprintf( 'Ignoring invalid cached file %s', $cacheFile ));
            unlink( $file ) or die( sprintf(
                "Couldn't remove %s: %s", $file, $!
            ));
        }
    }

    debug( sprintf( 'Downloading %s', $url ));
    my $response = LWP::UserAgent->new(
        agent     => "iMSCP/$::imscpConfig{'Version'}",
        timeout   => 60,
        env_proxy => TRUE
    )->get( $url, ':content_file' => $file );
    $response->is_success or die( sprintf(
        "Couldn't download %s: %s", $url, $response->status_line
    ));

    my $got = _sha256( $file );
    $got eq $sha256 or die( sprintf(
        "Checksum mismatch for %s (expected SHA-256: %s, got: %s)",
        $url, $sha256, $got
    ));

    ( $file, FALSE );
}

=item _storeInCache( $fh, $cacheFile )

 Store the given verified file in the cache (as the control panel user)

 Failures are not fatal (the cache is optional).

 Param filehandle $fh Filehandle of verified file
 Param string $cacheFile Path of cached file
 Return void

=cut

sub _storeInCache
{
    my ( $fh, $cacheFile ) = @_;

    local $@;
    eval {
        iMSCP::Dir->new( dirname => dirname( $cacheFile ))->make( {
            mode => 0750
        } );
        seek( $fh, 0, 0 ) or die( sprintf( "Couldn't seek: %s", $! ));
        binmode( $fh );
        _writeFile( $cacheFile, do { local $/; <$fh> }, 0640 );
    };
    debug( sprintf( "Couldn't cache %s: %s", $cacheFile, $@ )) if $@;
}

=item _checkArchive( $archive )

 Check members of the given (verified) tar.gz archive

 Absolute paths and paths containing '..' segments are refused.

 Param string $archive Archive path
 Return void, die on failure

=cut

sub _checkArchive
{
    my ( $archive ) = @_;

    my $rs = execute(
        [ '/bin/tar', '--list', '--gzip', '--file', $archive ],
        \my $stdout,
        \my $stderr
    );
    $rs == 0 or die( sprintf(
        "Couldn't list content of %s: %s", $archive, $stderr || 'Unknown error'
    ));

    for my $member ( split /\n/, $stdout ) {
        $member !~ m%^/% && $member !~ m%(?:^|/)\.\.(?:/|$)% or die( sprintf(
            "Unsafe member in %s: %s", $archive, $member
        ));
    }
}

=item _extractArchive( $fh, $destDir )

 Extract the given (verified) tar.gz archive into the given directory, as the
 control panel user (must be called through _runAsPanelUser())

 The first path component is stripped. Setuid/setgid/sticky bits are removed,
 and symlinks pointing outside of the destination directory as well as
 special files are refused.

 Param filehandle $fh Filehandle of the verified archive
 Param string $destDir Destination directory
 Return void, die on failure

=cut

sub _extractArchive
{
    my ( $fh, $destDir ) = @_;

    seek( $fh, 0, 0 ) or die( sprintf( "Couldn't seek: %s", $! ));
    open( STDIN, '<&', $fh ) or die( sprintf( "Couldn't dup archive filehandle: %s", $! ));

    my $rs = execute(
        [
            '/bin/tar', '--extract', '--gzip',
            '--file', '-',
            '--directory', $destDir,
            '--strip-components=1',
            '--no-same-owner',
            '--no-same-permissions'
        ],
        \my $stdout,
        \my $stderr
    );
    debug( $stdout ) if length $stdout;
    $rs == 0 or die( sprintf(
        "Couldn't extract archive: %s", $stderr || 'Unknown error'
    ));

    my $realDestDir = Cwd::realpath( $destDir ) // die( sprintf(
        "Couldn't resolve %s: %s", $destDir, $!
    ));

    File::Find::find(
        {
            wanted   => sub {
                my $path = $_;
                lstat( $path ) or die( sprintf(
                    "Couldn't stat %s: %s", $path, $!
                ));

                if ( -l _ ) {
                    my $target = readlink( $path ) // die( sprintf(
                        "Couldn't read %s symlink: %s", $path, $!
                    ));
                    die( sprintf( 'Unsafe symlink: %s -> %s', $path, $target ))
                        if $target =~ m%^/%;

                    # Lexical resolution (relative to the symlink location)
                    my @segments = grep { $_ ne '' && $_ ne '.' } File::Spec->splitdir(
                        File::Spec->abs2rel( dirname( $path ), $destDir )
                    );
                    for my $segment ( File::Spec->splitdir( $target ) ) {
                        next if $segment eq '' || $segment eq '.';
                        if ( $segment eq '..' ) {
                            @segments or die( sprintf(
                                'Unsafe symlink: %s -> %s', $path, $target
                            ));
                            pop @segments;
                            next;
                        }
                        push @segments, $segment;
                    }

                    # Physical resolution (symlink chains)
                    my $realPath = Cwd::realpath( $path );
                    !defined $realPath
                        || $realPath eq $realDestDir
                        || index( $realPath, "$realDestDir/" ) == 0 or die(
                        sprintf( 'Unsafe symlink: %s -> %s', $path, $target )
                    );
                    return;
                }

                -f _ || -d _ or die( sprintf( 'Unsafe special file: %s', $path ));

                my $mode = ( lstat _ )[2] & 07777;
                if ( $mode & ( S_ISUID | S_ISGID | S_ISVTX ) ) {
                    chmod( $mode & 00777, $path ) or die( sprintf(
                        "Couldn't set permissions on %s: %s", $path, $!
                    ));
                }
            },
            no_chdir => TRUE,
            follow   => FALSE
        },
        $destDir
    );
}

=item _removeDirAsPanelUser( @dirs )

 Remove the given directories (if any) as the control panel user

 Param list @dirs Directories
 Return void, die on failure

=cut

sub _removeDirAsPanelUser
{
    my ( @dirs ) = @_;

    # The control panel user can be already removed (uninstaller context)
    unless ( defined getpwnam(
        $::imscpConfig{'SYSTEM_USER_PREFIX'} . $::imscpConfig{'SYSTEM_USER_MIN_UID'}
    ) ) {
        iMSCP::Dir->new( dirname => $_ )->remove() for @dirs;
        return;
    }

    _runAsPanelUser( sub {
        iMSCP::Dir->new( dirname => $_ )->remove() for @dirs;
    } );
}

=back

=head1 AUTHOR

 Laurent Declercq <l.declercq@nuxwin.com>

=cut

1;
__END__
