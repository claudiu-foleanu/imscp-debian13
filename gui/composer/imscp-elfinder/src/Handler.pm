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
use Digest::SHA;
use File::Basename qw/ basename dirname /;
use File::Spec;
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
        iMSCP::Dir->new( dirname => "$CWD/data/tmp/elfinder" )->make( {
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

    local $CWD = $::imscpConfig{'GUI_ROOT_DIR'};

    my $pkgDir = "$CWD/vendor/imscp/elfinder";

    local $@;
    eval {
        # Symlinks to the upstream static assets
        iMSCP::Dir->new( dirname => "$pkgDir/public/ui" )->remove();
        iMSCP::Dir->new( dirname => "$pkgDir/public/ui" )->make( {
            user  => $::imscpConfig{'SYSTEM_USER_PREFIX'}
                . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
            group => $::imscpConfig{'SYSTEM_USER_PREFIX'}
                . $::imscpConfig{'SYSTEM_USER_MIN_UID'},
            mode  => 0750
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
        if ( -l "$CWD/public/tools/elfinder" ) {
            unlink( "$CWD/public/tools/elfinder" ) or die( sprintf(
                "Couldn't remove the %s symlink: %s",
                "$CWD/public/tools/elfinder", $!
            ));
        }

        symlink(
            File::Spec->abs2rel( "$pkgDir/public", "$CWD/public/tools" ),
            "$CWD/public/tools/elfinder"
        ) or die( sprintf(
            "Couldn't create symlink for the elFinder file manager: %s", $!
        ));
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
        iMSCP::Dir->new( dirname => "$CWD/vendor/imscp/elfinder/public/ui" )->remove();
        iMSCP::Dir->new( dirname => "$CWD/vendor/imscp/elfinder/elfinder" )->remove();
        iMSCP::Dir->new( dirname => "$CWD/data/tmp/elfinder" )->remove();
        iMSCP::Dir->new( dirname => $self->_getCacheDir())->remove();
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

=item _fetch( $url, $sha256, $cacheDir, $name )

 Download (or reuse cached) file and verify its SHA-256 checksum

 Param string $url URL
 Param string $sha256 Expected SHA-256 checksum
 Param string $cacheDir Cache directory
 Param string $name Cached file name
 Return string Path to the verified file, die on failure

=cut

sub _fetch
{
    my ( undef, $url, $sha256, $cacheDir, $name ) = @_;

    my $file = "$cacheDir/$name";
    return $file if -f $file && _sha256( $file ) eq $sha256;

    unlink( $file );
    debug( sprintf( 'Downloading %s', $url ));

    my $response = LWP::UserAgent->new(
        agent     => "iMSCP/$::imscpConfig{'Version'}",
        timeout   => 60,
        env_proxy => TRUE
    )->get( $url, ':content_file' => "$file.part" );
    unless ( $response->is_success ) {
        unlink( "$file.part" );
        die( sprintf( "Couldn't download %s: %s", $url, $response->status_line ));
    }

    my $got = _sha256( "$file.part" );
    unless ( $got eq $sha256 ) {
        unlink( "$file.part" );
        die( sprintf(
            "Checksum mismatch for %s (expected SHA-256: %s, got: %s)",
            $url, $sha256, $got
        ));
    }

    rename( "$file.part", $file ) or die( sprintf(
        "Couldn't rename %s.part to %s: %s", $file, $file, $!
    ));

    $file;
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
    my $ug = $::imscpConfig{'SYSTEM_USER_PREFIX'}
        . $::imscpConfig{'SYSTEM_USER_MIN_UID'};

    if ( -f "$appDir/.imscp-upstream" && -f "$appDir/php/elFinder.class.php" ) {
        my $curStamp = iMSCP::File->new(
            filename => "$appDir/.imscp-upstream"
        )->get() // '';
        chomp( $curStamp );
        if ( $curStamp eq $stamp ) {
            debug( sprintf(
                'elFinder %s is already installed. Skipping download.',
                $UPSTREAM{'version'}
            ));
            return 0;
        }
    }

    local $@;
    eval {
        -d $pkgDir or die( sprintf(
            "The %s directory doesn't exist. The imscp/elfinder composer package is not installed.",
            $pkgDir
        ));

        # Download (or reuse cached) files and verify their checksum
        my $cacheDir = $self->_getCacheDir();
        iMSCP::Dir->new( dirname => $cacheDir )->make( {
            user  => $ug,
            group => $ug,
            mode  => 0750
        } );

        my $archive = $self->_fetch(
            $UPSTREAM{'url'}, $UPSTREAM{'sha256'}, $cacheDir, $UPSTREAM{'file'}
        );

        my @assets = map {
            my $name = $_->[1] =~ s%/%_%gr;
            [ $self->_fetch( $_->[0], $_->[2], $cacheDir, $name ), $_->[1] ];
        } @ASSETS;

        # Extract the archive into a staging directory
        my $newDir = "$pkgDir/.elfinder.new";
        my $oldDir = "$pkgDir/.elfinder.old";
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
            "Couldn't extract the elFinder %s release archive: %s",
            $UPSTREAM{'version'}, $stderr || 'Unknown error'
        ));

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
            next unless -e "$newDir/$file";
            unlink( "$newDir/$file" ) or die( sprintf(
                "Couldn't remove %s: %s", "$newDir/$file", $!
            ));
        }

        # Client-side libraries
        for my $asset ( @assets ) {
            my ( $src, $dst ) = @{ $asset };
            iMSCP::Dir->new( dirname => dirname( "$newDir/$dst" ))->make();
            iMSCP::File->new( filename => $src )->copyFile(
                "$newDir/$dst", { preserve => 'no' }
            ) == 0 or die( "Couldn't copy $src to $newDir/$dst" );
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

=item _buildConfigFile( )

 Build elFinder front-end configuration file

 Return int 0 on success, other on failure

=cut

sub _buildConfigFile
{
    my ( $self ) = @_;

    local $@;
    my $rs = eval {
        my $cfgFile = "$CWD/vendor/imscp/elfinder/config.php";

        # Keep the secret key (and therefore the active sessions) if any
        my $secretKey;
        if ( -f $cfgFile ) {
            my $content = iMSCP::File->new( filename => $cfgFile )->get() // '';
            ( $secretKey ) = $content =~ /'secret_key'\s*=>\s*'([0-9a-f]{64})'/;
        }
        $secretKey //= randomStr( 64, '0123456789abcdef' );

        my $data = {
            FTP_SSL         => ::setupGetQuestion( 'SERVICES_SSL_ENABLED' ) eq 'yes'
                ? 'true' : 'false',
            TMP_DIR         => "$CWD/data/tmp/elfinder",
            SECRET_KEY      => $secretKey,
            UPLOAD_MAX_SIZE => '128M',
            TIMEZONE        => ::setupGetQuestion( 'TIMEZONE' ) || 'UTC'
        };

        my $rs = $self->{'events'}->trigger(
            'onLoadTemplate', 'elfinder', 'config.php', \my $cfgTpl, $data
        );
        return $rs if $rs;

        unless ( defined $cfgTpl ) {
            $cfgTpl = iMSCP::File->new(
                filename => "$CWD/vendor/imscp/elfinder/src/config.php"
            )->get();
            return 1 unless defined $cfgTpl;
        }

        # Values are put in single-quoted PHP strings
        $data->{$_} =~ s/(['\\])/\\$1/g for qw/ TMP_DIR UPLOAD_MAX_SIZE TIMEZONE /;

        my $file = iMSCP::File->new( filename => $cfgFile );
        $file->set( process( $data, $cfgTpl ));
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

 Build httpd configuration file for elFinder

 Return int 0 on success, other on failure

=cut

sub _buildHttpdConfigFile
{
    my $rs = iMSCP::File->new(
        filename => "$CWD/vendor/imscp/elfinder/src/nginx.conf"
    )->copyFile( '/etc/nginx/imscp_elfinder.conf' );
    return $rs if $rs;

    my $file = iMSCP::File->new( filename => '/etc/nginx/imscp_elfinder.conf' );
    return 1 unless defined( my $fileC = $file->getAsRef());

    ${ $fileC } = process( { GUI_ROOT_DIR => $CWD }, ${ $fileC } );

    $file->save();
}

=back

=head1 AUTHOR

 Laurent Declercq <l.declercq@nuxwin.com>

=cut

1;
__END__
