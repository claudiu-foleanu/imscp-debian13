#!/usr/bin/perl

# i-MSCP SGW_LetsEncrypt plugin - certbot mock (test mode only)
# Copyright (C) 2017 Cambell Prince <cambell.prince@gmail.com>
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

# Minimal certbot replacement used when the plugin 'test_mode' configuration
# parameter is enabled. It emulates the certbot sub-commands used by the
# plugin (certonly, delete, revoke, renew) and issues certificates from a
# local test CA, using the certbot directory layout (live/, archive/,
# renewal/) under the directory given by --config-dir. It never contacts any
# ACME server, so the i-MSCP integration can be tested with domains that
# don't resolve publicly.
#
# - certonly fails for any domain starting with "fail." (error path testing)
# - renew re-issues the lineages (all, or the one given by --cert-name) and
#   runs the deploy hooks found in /etc/letsencrypt/renewal-hooks/deploy with
#   RENEWED_LINEAGE/RENEWED_DOMAINS set, as certbot does.
#
# Usage: certbot-mock.pl --config-dir DIR SUBCOMMAND [options]

use strict;
use warnings;
use File::Path qw/ make_path remove_tree /;
use File::Temp;

my %opts = ( domains => [] );
my $command;
my @args = @ARGV;
while ( @args ) {
    my $arg = shift @args;
    if ( $arg =~ /^--(config-dir|cert-name|webroot-path|key-type|email|server|reason)$/ || $arg eq '-w' || $arg eq '-m' ) {
        my $key = { '-w' => 'webroot-path', '-m' => 'email' }->{$arg} // $1;
        $opts{$key} = shift @args;
    } elsif ( $arg eq '--domain' || $arg eq '-d' ) {
        push @{ $opts{'domains'} }, split /,/, shift @args;
    } elsif ( $arg =~ /^--(test-cert|staging|force-renewal|renew-by-default)$/ ) {
        $opts{$1} = 1;
    } elsif ( $arg =~ /^-/ ) {
        # Other flags are accepted and ignored (--non-interactive, --agree-tos, ...)
    } elsif ( !defined $command ) {
        $command = $arg;
    } else {
        die "Unexpected argument: $arg\n";
    }
}

my $configDir = $opts{'config-dir'} or die "--config-dir is required\n";
$configDir =~ m%^/[A-Za-z0-9._/-]+\z% or die "Invalid --config-dir\n";
$command //= '';

sub validName
{
    my ( $name ) = @_;
    defined $name && $name =~ /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\z/ && $name !~ /\.\./;
}

sub run
{
    # openssl writes progress information on STDERR
    my $pid = fork() // die "Couldn't fork: $!\n";
    unless ( $pid ) {
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';
        exec { $_[0] } @_ or exit 127;
    }
    waitpid( $pid, 0 );
    $? == 0 or die sprintf( "Command failed: %s\n", join ' ', @_ );
}

sub readFile
{
    my ( $file ) = @_;
    open my $fh, '<', $file or return undef;
    local $/;
    my $content = <$fh>;
    close $fh;
    $content;
}

sub writeFile
{
    my ( $file, $content, $mode ) = @_;
    open my $fh, '>', $file or die "Couldn't write $file: $!\n";
    print { $fh } $content;
    close $fh;
    chmod $mode // 0644, $file;
}

sub lineageDomains
{
    my ( $name ) = @_;
    my $conf = readFile( "$configDir/renewal/$name.conf" ) // '';
    my ( $domains ) = $conf =~ /^# mock_domains = (.*)$/m;
    defined $domains ? split( /,/, $domains ) : ();
}

sub issue
{
    my ( $name, $domains, $keyType, $webroot, $staging ) = @_;

    umask 022;
    my $caDir = "$configDir/mock-ca";
    make_path( $caDir, "$configDir/live/$name", "$configDir/archive/$name", "$configDir/renewal",
        { mode => 0755 } );
    chmod 0700, $caDir;

    unless ( -f "$caDir/ca.pem" ) {
        run( 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', "$caDir/ca.key",
            '-out', "$caDir/ca.pem", '-days', '3650', '-subj', '/O=SGW_LetsEncrypt mock/CN=SGW_LetsEncrypt mock CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign' );
    }

    my $n = 1;
    $n++ while -e "$configDir/archive/$name/cert$n.pem";

    my $tmp = File::Temp->newdir();
    my $key = "$configDir/archive/$name/privkey$n.pem";
    run( 'openssl', 'req', '-new', '-nodes', '-keyout', $key, '-out', "$tmp/req.csr", '-subj', "/CN=$name",
        ( ( $keyType // 'rsa' ) eq 'ecdsa'
            ? ( '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1' ) : ( '-newkey', 'rsa:2048' ) ) );
    chmod 0600, $key;

    writeFile( "$tmp/ext.cnf", join( "\n",
        'basicConstraints=CA:FALSE',
        'keyUsage=critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage=serverAuth',
        'subjectAltName=' . join( ',', map { "DNS:$_" } @{ $domains } ),
        ''
    ));

    run( 'openssl', 'x509', '-req', '-in', "$tmp/req.csr", '-CA', "$caDir/ca.pem", '-CAkey', "$caDir/ca.key",
        '-set_serial', '0x' . join( '', map { sprintf '%02x', int rand 256 } 1 .. 16 ), '-days', '90', '-sha256',
        '-extfile', "$tmp/ext.cnf", '-out', "$configDir/archive/$name/cert$n.pem" );

    my $cert = readFile( "$configDir/archive/$name/cert$n.pem" );
    my $chain = readFile( "$caDir/ca.pem" );
    writeFile( "$configDir/archive/$name/chain$n.pem", $chain );
    writeFile( "$configDir/archive/$name/fullchain$n.pem", $cert . $chain );

    for my $part ( qw/ cert chain fullchain privkey / ) {
        unlink "$configDir/live/$name/$part.pem";
        symlink "../../archive/$name/$part$n.pem", "$configDir/live/$name/$part.pem"
            or die "Couldn't create symlink: $!\n";
    }

    my $server = $staging
        ? 'https://acme-staging-v02.api.letsencrypt.org/directory' : 'https://acme-v02.api.letsencrypt.org/directory';
    writeFile( "$configDir/renewal/$name.conf", <<"EOF" );
# renew_before_expiry = 30 days
# mock_domains = @{[ join ',', @{ $domains } ]}
version = 4.0.0
archive_dir = $configDir/archive/$name
cert = $configDir/live/$name/cert.pem
privkey = $configDir/live/$name/privkey.pem
chain = $configDir/live/$name/chain.pem
fullchain = $configDir/live/$name/fullchain.pem

# Options used in the renewal process
[renewalparams]
account = mock
authenticator = webroot
webroot_path = $webroot,
server = $server
key_type = @{[ $keyType // 'rsa' ]}
[[webroot_map]]
@{[ join "\n", map { "$_ = $webroot" } @{ $domains } ]}
EOF
}

if ( $command eq 'certonly' ) {
    my $name = $opts{'cert-name'} // $opts{'domains'}->[0];
    validName( $name ) or die "Invalid certificate name\n";
    @{ $opts{'domains'} } or die "No domain given\n";
    validName( $_ ) or die "Invalid domain: $_\n" for @{ $opts{'domains'} };
    defined $opts{'webroot-path'} or die "--webroot-path is required\n";

    if ( my ( $failed ) = grep { /^fail\./ } @{ $opts{'domains'} } ) {
        print STDERR "Certbot failed to authenticate some domains (authenticator: webroot).\n"
            . "  Domain: $failed\n  Type:   dns\n  Detail: mock failure (domains starting with 'fail.' always fail)\n";
        exit 1;
    }

    my @current = lineageDomains( $name );
    if ( @current && !$opts{'force-renewal'} && !$opts{'renew-by-default'}
        && join( ',', sort @current ) eq join( ',', sort @{ $opts{'domains'} } )
    ) {
        print "Certificate not yet due for renewal\n";
        exit 0;
    }

    issue( $name, $opts{'domains'}, $opts{'key-type'}, $opts{'webroot-path'}, $opts{'test-cert'} || $opts{'staging'} );
    print "Successfully received certificate.\nCertificate is saved at: $configDir/live/$name/fullchain.pem\n";
    exit 0;
}

if ( $command eq 'delete' ) {
    my $name = $opts{'cert-name'};
    validName( $name ) or die "Invalid certificate name\n";
    -f "$configDir/renewal/$name.conf" or die "No certificate found with name $name\n";
    remove_tree( "$configDir/live/$name", "$configDir/archive/$name" );
    unlink "$configDir/renewal/$name.conf";
    print "Deleted all files relating to certificate $name.\n";
    exit 0;
}

if ( $command eq 'revoke' ) {
    my $name = $opts{'cert-name'};
    validName( $name ) && -f "$configDir/renewal/$name.conf" or die "No certificate found with name\n";
    print "Congratulations! You have successfully revoked the certificate (mock).\n";
    exit 0;
}

if ( $command eq 'renew' ) {
    my @names;
    if ( defined $opts{'cert-name'} ) {
        validName( $opts{'cert-name'} ) or die "Invalid certificate name\n";
        @names = ( $opts{'cert-name'} );
    } elsif ( opendir( my $dh, "$configDir/renewal" ) ) {
        @names = sort map { s/\.conf\z//r } grep { /\.conf\z/ } readdir $dh;
        closedir $dh;
    }

    my $ret = 0;
    for my $name ( @names ) {
        my $conf = readFile( "$configDir/renewal/$name.conf" ) or next;
        my @domains = lineageDomains( $name );
        next unless @domains;
        my ( $webroot ) = $conf =~ /^webroot_path = ([^,\n]+)/m;
        my ( $keyType ) = $conf =~ /^key_type = (\S+)/m;
        issue( $name, \@domains, $keyType, $webroot // '/nonexistent', $conf =~ /^server = \S*staging/m );
        print "Renewed $name\n";

        my $hookDir = '/etc/letsencrypt/renewal-hooks/deploy';
        next unless opendir( my $dh, $hookDir );
        for my $hook ( sort grep { -f "$hookDir/$_" && -x _ } readdir $dh ) {
            local $ENV{'RENEWED_LINEAGE'} = "$configDir/live/$name";
            local $ENV{'RENEWED_DOMAINS'} = join ' ', @domains;
            if ( system( "$hookDir/$hook" ) != 0 ) {
                print STDERR "Hook '$hook' failed\n";
                $ret = 1;
            }
        }
        closedir $dh;
    }

    exit $ret;
}

die "Unsupported command: $command\n";
