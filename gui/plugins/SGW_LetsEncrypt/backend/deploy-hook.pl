#!/usr/bin/perl

# i-MSCP SGW_LetsEncrypt plugin - certbot deploy hook
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

# This file is a template. The plugin installs it as
# /etc/letsencrypt/renewal-hooks/deploy/imscp-sgw-letsencrypt when it is
# enabled, and removes it when it is disabled. DO NOT EDIT the installed copy.
#
# certbot runs it after each successful renewal ("certbot renew", run by the
# certbot.timer systemd unit), with the RENEWED_LINEAGE environment variable
# set to the live directory of the renewed certificate. If the lineage belongs
# to an active SGW_LetsEncrypt item, the renewed certificate is imported into
# the i-MSCP ssl_certs table, the i-MSCP certificate file is rebuilt through
# the i-MSCP SSL certificate module, and Apache is reloaded. Nothing else is
# changed. Lineages not managed by the plugin are ignored.

use strict;
use warnings;
use lib '{{ENGINE_ROOT_DIR}}/PerlLib', '{{ENGINE_ROOT_DIR}}/PerlVendor';
use File::Basename qw/ basename dirname /;

@{ENV}{qw/ LANG PATH /} = ( 'C.UTF-8', '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' );
delete $ENV{'LANGUAGE'};

my $lineage = $ENV{'RENEWED_LINEAGE'} // '';
$lineage =~ s%/+$%%;
my $name = basename( $lineage );

# Not a lineage name that this plugin could have created
exit 0 unless length $name <= 253
    && $name =~ /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\z/
    && -d $lineage
    && basename( dirname( $lineage )) eq 'live';

require iMSCP::Bootstrapper;
require iMSCP::Database;
require iMSCP::Debug;
require iMSCP::File;
require iMSCP::Service;

iMSCP::Debug::newDebug( 'imscp-sgw-letsencrypt-deploy-hook.log' );

# No lock: this hook must never wait for (or block) the i-MSCP backend. It
# only updates the certificate of the renewed lineage.
iMSCP::Bootstrapper->getInstance()->boot( {
    mode            => 'backend',
    nolock          => 1,
    config_readonly => 1
} );

my $configDir = dirname( dirname( $lineage ));
my $dbh = iMSCP::Database->factory()->getRawDb();

my $rows = eval {
    $dbh->selectall_arrayref(
        "SELECT domain_id, alias_id, subdomain_id FROM letsencrypt WHERE cert_name = ? AND status = 'ok'",
        { Slice => {} },
        $name
    );
};
# Table doesn't exist (plugin uninstalled) or no active item for this lineage
exit 0 if $@ || !$rows || !@{ $rows };

my %pem;
for my $part ( qw/ privkey cert chain / ) {
    my $content = iMSCP::File->new( filename => "$lineage/$part.pem" )->get();
    unless ( defined $content && $content =~ /-----BEGIN [A-Z ]+-----/ ) {
        print STDERR "Couldn't read $lineage/$part.pem\n";
        exit 1;
    }
    $pem{$part} = $content;
}

# Let's Encrypt staging roots aren't in the system trust store. Append them to
# the CA bundle for staging certificates, else i-MSCP rejects the chain.
my $renewalConf = iMSCP::File->new( filename => "$configDir/renewal/$name.conf" )->get() // '';
if ( $renewalConf =~ /^\s*server\s*=\s*\S*staging/m ) {
    $pem{'chain'} =~ s/\s*$/\n/;
    $pem{'chain'} .= <<'EOF';
{{STAGING_ROOTS}}
EOF
}

# Certificates of the lineage (current and previous versions)
my @lineageCerts;
if ( opendir( my $dh, "$configDir/archive/$name" ) ) {
    for my $file ( grep { /^cert\d+\.pem\z/ } readdir $dh ) {
        my $content = iMSCP::File->new( filename => "$configDir/archive/$name/$file" )->get();
        push @lineageCerts, $content =~ s/\s+//gr if defined $content;
    }
    closedir $dh;
}

require Modules::SSLcertificate;

my ( $updated, $ret ) = ( 0, 0 );
for my $row ( @{ $rows } ) {
    my ( $type, $id ) = $row->{'alias_id'}
        ? ( 'als', $row->{'alias_id'} )
        : ( $row->{'subdomain_id'} ? ( 'sub', $row->{'subdomain_id'} ) : ( 'dmn', $row->{'domain_id'} ) );

    my $cert = $dbh->selectrow_hashref(
        'SELECT cert_id, certificate FROM ssl_certs WHERE domain_type = ? AND domain_id = ?', undef, $type, $id
    );
    next unless $cert;

    # Don't overwrite a certificate which was replaced by the customer through
    # the i-MSCP SSL certificate interface.
    my $current = ( $cert->{'certificate'} // '' ) =~ s/\s+//gr;
    next unless grep ( $_ eq $current, @lineageCerts );

    $dbh->do(
        "UPDATE ssl_certs SET private_key = ?, certificate = ?, ca_bundle = ?, status = 'tochange' WHERE cert_id = ?",
        undef, @pem{qw/ privkey cert chain /}, $cert->{'cert_id'}
    );

    # Rebuild the i-MSCP certificate file (<GUI_ROOT_DIR>/data/certs/<domain>.pem)
    # exactly as the i-MSCP backend does. The status is updated by the module.
    if ( Modules::SSLcertificate->new()->process( { id => $cert->{'cert_id'} } ) ) {
        $ret = 1;
        next;
    }

    my ( $status ) = $dbh->selectrow_array( 'SELECT status FROM ssl_certs WHERE cert_id = ?', undef, $cert->{'cert_id'} );
    if ( defined $status && $status ne 'ok' ) {
        print STDERR "i-MSCP rejected the renewed $name certificate: $status\n";
        $ret = 1;
        next;
    }

    $updated++;
}

if ( $updated ) {
    my $service = eval {
        require Servers::httpd;
        Servers::httpd->factory()->{'config'}->{'HTTPD_SNAME'};
    } || 'apache2';

    eval { iMSCP::Service->getInstance()->reload( $service ); };
    if ( $@ ) {
        print STDERR $@;
        $ret = 1;
    }
}

exit $ret;
