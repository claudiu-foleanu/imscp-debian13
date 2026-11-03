=head1 NAME

 Plugin::OpenDMARC

=cut

# i-MSCP OpenDMARC plugin
# Copyright (C) 2026 i-MSCP Debian 13 port
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

package Plugin::OpenDMARC;

use strict;
use warnings;
use iMSCP::Database;
use iMSCP::Debug qw/ debug error warning getMessageByType /;
use iMSCP::Dir;
use iMSCP::Execute qw/ execute /;
use iMSCP::File;
use iMSCP::Service;
use iMSCP::TemplateParser qw/ replaceBloc /;
use iMSCP::SystemUser;
use Servers::mta;
use Cwd qw/ realpath /;
use Fcntl qw/ O_RDONLY O_NOFOLLOW O_NONBLOCK O_DIRECTORY S_ISDIR S_ISREG S_ISVTX S_IWGRP S_IWOTH /;
use File::Basename qw/ basename dirname /;
use File::Temp ();
use Text::Balanced qw/ extract_multiple extract_bracketed /;
use parent 'Common::SingletonClass';

# Owner of the DNS resource records in the domain_dns table
our $DNS_OWNER = 'OpenDMARC_Plugin';

# OpenDMARC configuration file and plugin configuration directory
our $CONF_FILE = '/etc/opendmarc.conf';
our $CONF_DIR = '/etc/opendmarc';
our $IGNORE_HOSTS_FILE = "$CONF_DIR/ignore.hosts";
our $OPENDMARC_BIN = '/usr/sbin/opendmarc';
our $PUBLIC_SUFFIX_LIST = '/usr/share/publicsuffix/public_suffix_list.dat';

my $BLOC_BEGIN = "# Begin Plugin::OpenDMARC\n";
my $BLOC_END = "# Ending Plugin::OpenDMARC\n";

# Marker used to comment out distribution opendmarc.conf(5) settings that are
# overridden by this plugin. Those lines are restored on deactivation.
my $CONF_COMMENT_MARKER = '#Plugin::OpenDMARC# ';

# opendmarc.conf(5) settings managed by this plugin (any distribution or
# administrator setting for them is commented out while the plugin is active)
my @MANAGED_CONF_KEYS = qw/
    AuthservID AuthservIDWithJobID FailureReports HistoryFile IgnoreAuthenticatedClients IgnoreHosts PidFile
    PublicSuffixList RejectFailures RequiredHeaders Socket SoftwareHeader SPFIgnoreResults SPFSelfValidate Syslog
    TrustedAuthservIDs UMask UserID
/;

# Valid (ASCII/punycode) domain name
our $DOMAIN_NAME_RE = qr/^(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i;

# Valid hostname (authserv-id). No comma (list separator), no whitespace.
our $HOSTNAME_RE = qr/^(?=.{1,253}\z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z/i;

# Valid report e-mail address (ASCII only). Characters with a special meaning
# in DMARC URIs (',', '!', ';') or in TXT records ('"', '\', whitespace) are
# excluded by construction.
our $EMAIL_RE = qr/^(?=.{3,254}\z)[a-z0-9_%+-]+(?:\.[a-z0-9_%+-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i;

# IPv4/IPv6 address or CIDR block
my $IPV4_RE = qr/^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\/(?:3[0-2]|[12]?\d))?\z/;
my $IPV6_RE = qr/^(?=.*:)[0-9a-f:.]{2,45}(?:\/(?:12[0-8]|1[01]\d|[1-9]?\d))?\z/i;

=head1 DESCRIPTION

 This package provides the backend part for the i-MSCP OpenDMARC plugin.

 Outbound: a _dmarc.<domain> TXT record is published for each customer domain
 and domain alias through the core domain_dns table (owned_by OpenDMARC_Plugin;
 published by the core Modules::CustomDNS module and the named server). Per-
 domain settings are stored in the opendmarc table (NULL = config.php default).
 A customer-defined _dmarc record (custom DNS feature) always wins: the plugin
 record is then withdrawn.

 Inbound: the opendmarc(8) milter (Debian package opendmarc 1.4.2) is
 configured through a managed block in /etc/opendmarc.conf and added to the
 Postfix smtpd_milters parameter right after the OpenDKIM milter, with a per-
 milter default_action (accept by default).

 Security notes:
  - Commands are always executed in list form (no shell).
  - All values written into configuration files are validated (_init()).
  - Configuration files are root-owned and written atomically (temporary file
    + rename(2)) in root-owned directories that are checked for untrusted
    path components. Ownership/permissions are only changed through file
    descriptors opened with O_NOFOLLOW. Symlinks are refused.
  - The socket directory (inside the Postfix queue directory) is owned by
    the opendmarc user (opendmarc(8) runs as that user and creates the
    socket) with mode 0750. The postfix user is added to the opendmarc group.
    The socket is created with mode 0660 (UMask 0117).

=head1 PUBLIC METHODS

=over 4

=item enable( )

 Perform enable tasks

 Return int 0 on success, other on failure

=cut

sub enable
{
    my ($self) = @_;

    local $@;
    eval {
        if ( grep ( $_ eq $self->{'action'}, 'install', 'update' ) || !-x $OPENDMARC_BIN ) {
            $self->_installDistributionPackages();
        }

        $self->_opendmarcSetup( 'configure' );
        $self->_postfixSetup( 'configure' );

        local $self->{'dbh'}->{'RaiseError'} = 1;

        # Re-render all records (defaults may have changed)
        $self->_syncEntries();
        $self->{'dbh'}->do( "UPDATE opendmarc SET opendmarc_status = 'tochange' WHERE opendmarc_status <> 'todelete'" );

        # Re-enable records disabled on plugin deactivation, except those of
        # suspended customers (re-enabled by the core with the customer)
        $self->{'dbh'}->do(
            "
                UPDATE domain_dns AS t1
                JOIN domain AS t2 USING(domain_id)
                SET t1.domain_dns_status = 'toenable'
                WHERE t1.owned_by = ?
                AND t1.domain_dns_status IN('disabled', 'todisable')
                AND t2.domain_status NOT IN('disabled', 'todisable')
            ",
            undef, $DNS_OWNER
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    $self->run();
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
                    WHERE owned_by = ?
                    AND domain_dns_status NOT IN('todelete', 'disabled')
                ",
                undef, $DNS_OWNER
            );
        }

        $self->_postfixSetup( 'deconfigure' );
        $self->_opendmarcSetup( 'deconfigure' );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item uninstall( )

 Perform uninstall tasks

 The plugin is already deactivated: its DNS records are disabled (removed
 from the zones) and the milter is unregistered.

 Return int 0 on success, other on failure

=cut

sub uninstall
{
    my ($self) = @_;

    local $@;
    eval {
        debug( 'Deleting all DMARC DNS records' );
        {
            local $self->{'dbh'}->{'RaiseError'} = 1;
            $self->{'dbh'}->do( 'DELETE FROM domain_dns WHERE owned_by = ?', undef, $DNS_OWNER );
        }

        if ( lstat $CONF_DIR ) {
            die( sprintf( 'Refusing to remove %s: not a directory (symlink?)', $CONF_DIR )) if -l _ || !-d _;
            debug( "Removing $CONF_DIR directory" );
            iMSCP::Dir->new( dirname => $CONF_DIR )->remove();
        }

        $self->_uninstallDistributionPackages();
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item run( )

 Process OpenDMARC entries and make sure that the milter is still correctly
 placed (after the OpenDKIM milter)

 Return int 0 on success, other on failure

=cut

sub run
{
    my ($self) = @_;

    local $@;
    eval {
        local $self->{'dbh'}->{'RaiseError'} = 1;

        $self->_syncEntries();

        my $rows = $self->{'dbh'}->selectall_arrayref(
            "
                SELECT opendmarc_id, domain_id, IFNULL(alias_id, 0) AS alias_id, domain_name, policy,
                    subdomain_policy, pct, adkim, aspf, rua, ruf, opendmarc_status
                FROM opendmarc
                WHERE opendmarc_status IN('toadd', 'tochange', 'todelete')
            ",
            { Slice => {} }
        );

        for my $row ( @{$rows} ) {
            local $@;
            eval {
                if ( $row->{'opendmarc_status'} eq 'todelete' ) {
                    $self->_unpublish( $row );
                    $self->{'dbh'}->do( 'DELETE FROM opendmarc WHERE opendmarc_id = ?', undef, $row->{'opendmarc_id'} );
                    return;
                }

                $self->_publish( $row );
                $self->{'dbh'}->do(
                    "UPDATE opendmarc SET opendmarc_status = 'ok' WHERE opendmarc_id = ?", undef, $row->{'opendmarc_id'}
                );
            };
            if ( $@ ) {
                my $err = $@;
                $err =~ s/\s+at\s+\S+\s+line\s+\d+\.?\s*$//;
                $self->{'dbh'}->do(
                    'UPDATE opendmarc SET opendmarc_status = ? WHERE opendmarc_id = ?',
                    undef, ( getMessageByType( 'error', { amount => 1, remove => 1 } ) || $err || 'Unknown error' ),
                    $row->{'opendmarc_id'}
                );
            }
        }

        $self->_checkMilterOrder() if $self->{'action'} eq 'run';
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item renderRecord( \%params )

 Render the DMARC TXT record data (without quotes) from the given effective
 parameters (policy, subdomain_policy, pct, adkim, aspf, rua, ruf)

 Param hashref \%params
 Return string, die on invalid parameter

=cut

sub renderRecord
{
    my (undef, $p) = @_;

    _validatePolicyParams( $p, 'record' );

    my @tags = ( 'v=DMARC1', "p=$p->{'policy'}" );
    push @tags, "sp=$p->{'subdomain_policy'}" if length $p->{'subdomain_policy'};
    push @tags, "pct=" . ( $p->{'pct'} + 0 ) if $p->{'pct'} != 100;
    push @tags, 'rua=mailto:' . lc( $p->{'rua'} ) if length $p->{'rua'};
    push @tags, 'ruf=mailto:' . lc( $p->{'ruf'} ) if length $p->{'ruf'};
    push @tags, "adkim=$p->{'adkim'}", "aspf=$p->{'aspf'}";

    my $record = join '; ', @tags;
    $record =~ /^[\x21-\x7e ]+\z/ && $record !~ /["\\]/ or die( 'Invalid DMARC record' );
    $record;
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 Initialize plugin

 Return Plugin::OpenDMARC, die on failure

=cut

sub _init
{
    my ($self) = @_;

    my @params = qw/
        dmarc_policy dmarc_subdomain_policy dmarc_pct dmarc_adkim dmarc_aspf dmarc_rua dmarc_ruf dmarc_dns_records_ttl
        customer_can_edit opendmarc_reject_failures opendmarc_authserv_id opendmarc_trusted_authserv_ids
        opendmarc_ignore_hosts opendmarc_socket opendmarc_user opendmarc_group postfix_milter_socket
        postfix_milter_default_action
    /;

    for my $param ( @params ) {
        defined $self->{'config'}->{$param} or die(
            sprintf( "Missing or undefined `%s' plugin configuration parameter", $param )
        );
    }

    $self->{'config_prev'} ||= {};
    for my $param ( keys %{$self->{'config'}} ) {
        $self->{'config_prev'}->{$param} //= $self->{'config'}->{$param};
    }

    _validateConfig( $self->{'config'} );
    $self->{'dbh'} = iMSCP::Database->factory()->getRawDb() unless $self->{'dbh'};
    $self;
}

=item _validateConfig( \%config )

 Validate the plugin configuration (values end in DNS records and in
 configuration files)

 Param hashref \%config
 Return void, die on failure

=cut

sub _validateConfig
{
    my ($c) = @_;

    _validatePolicyParams(
        {
            policy           => $c->{'dmarc_policy'},
            subdomain_policy => $c->{'dmarc_subdomain_policy'},
            pct              => $c->{'dmarc_pct'},
            adkim            => $c->{'dmarc_adkim'},
            aspf             => $c->{'dmarc_aspf'},
            rua              => $c->{'dmarc_rua'},
            ruf              => $c->{'dmarc_ruf'}
        },
        'config'
    );

    $c->{'dmarc_dns_records_ttl'} =~ /^\d{1,5}\z/ && $c->{'dmarc_dns_records_ttl'} >= 60
        && $c->{'dmarc_dns_records_ttl'} <= 86400 or die( "Invalid `dmarc_dns_records_ttl' parameter. Integer 60..86400 expected." );
    $c->{'opendmarc_authserv_id'} =~ $HOSTNAME_RE or die( "Invalid `opendmarc_authserv_id' parameter. Hostname expected." );

    ref $c->{'opendmarc_trusted_authserv_ids'} eq 'ARRAY' or die(
        "Invalid `opendmarc_trusted_authserv_ids' parameter. Array expected."
    );
    for ( @{$c->{'opendmarc_trusted_authserv_ids'}} ) {
        defined && $_ =~ $HOSTNAME_RE or die( "Invalid entry in the `opendmarc_trusted_authserv_ids' parameter." );
    }

    ref $c->{'opendmarc_ignore_hosts'} eq 'ARRAY' or die( "Invalid `opendmarc_ignore_hosts' parameter. Array expected." );
    for ( @{$c->{'opendmarc_ignore_hosts'}} ) {
        defined && _isValidHostEntry( $_ ) or die( "Invalid entry in the `opendmarc_ignore_hosts' parameter." );
    }

    $c->{'opendmarc_socket'} =~ m%^local:/[A-Za-z0-9_./-]+/[A-Za-z0-9_.-]+\z% && $c->{'opendmarc_socket'} !~ m%/\.\.?(?:/|\z)%
        or die( "Invalid `opendmarc_socket' parameter. local:/path/to/socket expected." );
    $c->{'postfix_milter_socket'} =~ m%^(?:unix:/[A-Za-z0-9_./-]+|inet:[A-Za-z0-9.-]+:\d{1,5})\z% or die(
        "Invalid `postfix_milter_socket' parameter."
    );
    $c->{'postfix_milter_default_action'} =~ /^(?:accept|reject|tempfail|quarantine)\z/ or die(
        "Invalid `postfix_milter_default_action' parameter."
    );
    for ( qw/ opendmarc_user opendmarc_group / ) {
        $c->{$_} =~ /^[a-z_][a-z0-9_-]{0,31}\z/ or die( "Invalid `$_' parameter." );
    }
    for ( qw/ customer_can_edit opendmarc_reject_failures / ) {
        # PHP booleans are decoded as JSON::PP::Boolean objects (1/0)
        my $v = "$c->{$_}";
        $v =~ /^(?:|0|1|true|false)\z/ or die( "Invalid `$_' parameter. Boolean expected." );
    }
}

=item _validatePolicyParams( \%params, $context )

 Validate DMARC policy parameters

 Param hashref \%params Parameters
 Param string $context Context for error messages
 Return void, die on failure

=cut

sub _validatePolicyParams
{
    my ($p, $context) = @_;

    for ( qw/ policy subdomain_policy pct adkim aspf rua ruf / ) {
        defined $p->{$_} or die( sprintf( 'Missing DMARC %s parameter (%s)', $_, $context ));
    }

    $p->{'policy'} =~ /^(?:none|quarantine|reject)\z/ or die( sprintf( 'Invalid DMARC policy (%s)', $context ));
    $p->{'subdomain_policy'} =~ /^(?:|none|quarantine|reject)\z/ or die(
        sprintf( 'Invalid DMARC subdomain policy (%s)', $context )
    );
    $p->{'pct'} =~ /^\d{1,3}\z/ && $p->{'pct'} >= 1 && $p->{'pct'} <= 100 or die(
        sprintf( 'Invalid DMARC pct value. Integer 1..100 expected (%s)', $context )
    );
    $p->{$_} =~ /^[rs]\z/ or die( sprintf( 'Invalid DMARC %s value (%s)', $_, $context )) for qw/ adkim aspf /;
    for ( qw/ rua ruf / ) {
        next if $p->{$_} eq '';
        $p->{$_} =~ $EMAIL_RE or die( sprintf( 'Invalid DMARC %s address (%s)', $_, $context ));
    }
}

=item _isValidHostEntry( $entry )

 Is the given entry a valid IgnoreHosts entry (IP address, CIDR block or hostname)?

 Param string $entry
 Return bool

=cut

sub _isValidHostEntry
{
    my ($entry) = @_;

    defined $entry && ( $entry =~ $IPV4_RE || $entry =~ $IPV6_RE || $entry =~ $HOSTNAME_RE );
}

=item _effectiveParams( \%row )

 Merge the given per-domain settings with the config.php defaults

 Param hashref \%row opendmarc table row
 Return hashref

=cut

sub _effectiveParams
{
    my ($self, $row) = @_;

    my $c = $self->{'config'};
    my %p;
    for ( [ 'policy', 'dmarc_policy' ], [ 'subdomain_policy', 'dmarc_subdomain_policy' ], [ 'pct', 'dmarc_pct' ],
        [ 'adkim', 'dmarc_adkim' ], [ 'aspf', 'dmarc_aspf' ], [ 'rua', 'dmarc_rua' ], [ 'ruf', 'dmarc_ruf' ]
    ) {
        $p{$_->[0]} = defined $row->{$_->[0]} ? $row->{$_->[0]} : $c->{$_->[1]};
    }

    \%p;
}

=item _installDistributionPackages( )

 Install the opendmarc distribution package (non-interactive)

 The opendmarc package can create a MySQL database for aggregate reports
 through dbconfig-common. This is disabled through debconf preseeding:
 reporting isn't used by this plugin.

 Return void, die on failure

=cut

sub _installDistributionPackages
{
    debug( 'Installing distribution packages' );

    local $ENV{'DEBIAN_FRONTEND'} = 'noninteractive';
    local $ENV{'UCF_FORCE_CONFFOLD'} = 1;

    # Preseed debconf (root-owned private temporary directory)
    my $tmpDir = File::Temp->newdir( 'opendmarc-XXXXXXXX', TMPDIR => 1, CLEANUP => 1 );
    my $selections = "$tmpDir/selections";
    _writeFileAtomic( $selections, "opendmarc opendmarc/dbconfig-install boolean false\n", 0, 0, 0600 );

    my ($stdout, $stderr);
    execute( [ 'debconf-set-selections', $selections ], \$stdout, \$stderr ) == 0 or die(
        sprintf( "Couldn't preseed debconf: %s", $stderr || 'Unknown error' )
    );

    execute( [ 'apt-get', 'update' ], \$stdout, \$stderr ) == 0 or die(
        sprintf( "Couldn't update APT index: %s", $stderr || 'Unknown error' )
    );
    debug( $stdout ) if $stdout;
    execute(
        [
            'apt-get', '-o', 'DPkg::Options::=--force-confold', '-o', 'DPkg::Options::=--force-confdef',
            '-o', 'DPkg::Options::=--force-confmiss', '--assume-yes', '--no-install-recommends', '--quiet',
            'install', 'opendmarc', 'publicsuffix'
        ],
        \$stdout, \$stderr
    ) == 0 or die( sprintf( "Couldn't install distribution packages: %s", $stderr || 'Unknown error' ));
    debug( $stdout ) if $stdout;
}

=item _uninstallDistributionPackages( )

 Uninstall the opendmarc distribution package (non-interactive)

 Return void, die on failure

=cut

sub _uninstallDistributionPackages
{
    debug( 'Uninstalling distribution packages' );
    local $ENV{'DEBIAN_FRONTEND'} = 'noninteractive';
    my $stderr;
    execute( [ 'apt-get', '--assume-yes', '--purge', '--quiet', 'remove', 'opendmarc' ], \my $stdout, \$stderr ) == 0
        or die( sprintf( "Couldn't uninstall distribution packages: %s", $stderr || 'Unknown error' ));
    debug( $stdout ) if $stdout;
}

=item _getSocketDir( $socket )

 Get the directory of the given OpenDMARC UNIX socket

 Param string $socket OpenDMARC socket specification (local:/path/to/socket)
 Return string|undef

=cut

sub _getSocketDir
{
    my (undef, $socket) = @_;

    return unless defined $socket && $socket =~ m%^(?:local|unix):(/.+)/[^/]+\z%;
    $1;
}

=item _getQueueDir( )

 Get the Postfix queue directory

 Return string

=cut

sub _getQueueDir
{
    my $queueDir = Servers::mta->factory()->{'config'}->{'POSTFIX_QUEUE_DIR'} || '/var/spool/postfix';
    $queueDir =~ s%/+$%%;
    $queueDir;
}

=item _postconfGet( $param )

 Get the value of the given Postfix main.cf parameter

 Param string $param Parameter name
 Return string, die on failure

=cut

sub _postconfGet
{
    my (undef, $param) = @_;

    my $confdir = Servers::mta->factory()->{'config'}->{'POSTFIX_CONF_DIR'} || '/etc/postfix';
    my ($stdout, $stderr);
    execute( [ 'postconf', '-c', $confdir, '-h', $param ], \$stdout, \$stderr ) == 0 or die(
        sprintf( "Couldn't get the Postfix %s parameter: %s", $param, $stderr || 'Unknown error' )
    );
    $stdout // '';
}

=item _buildIgnoreHosts( )

 Build the list of hosts whose connections are ignored by OpenDMARC

 Return list

=cut

sub _buildIgnoreHosts
{
    my ($self) = @_;

    my @hosts = ( '127.0.0.1', '::1' );

    # Postfix mynetworks (lookup tables and files are skipped)
    for my $entry ( split /[\s,]+/, $self->_postconfGet( 'mynetworks' ) ) {
        next unless length $entry;
        $entry =~ s%^\[([^\]]+)\](/\d+)?$%$1 . ( $2 // '' )%e;
        unless ( _isValidHostEntry( $entry ) ) {
            debug( sprintf( 'Skipping unsupported mynetworks entry: %s', $entry ));
            next;
        }
        push @hosts, $entry;
    }

    push @hosts, @{$self->{'config'}->{'opendmarc_ignore_hosts'}};
    my %seen;
    grep { !$seen{lc $_}++ } @hosts;
}

=item _buildTrustedAuthservIds( )

 Build the list of trusted authserv-ids

 Return list

=cut

sub _buildTrustedAuthservIds
{
    my ($self) = @_;

    my @ids = ( $self->{'config'}->{'opendmarc_authserv_id'} );

    # OpenDKIM uses the MTA name ({j} macro, Postfix myhostname) by default
    my $myhostname = $self->_postconfGet( 'myhostname' );
    $myhostname =~ s/^\s+|\s+$//g;
    push @ids, $myhostname if $myhostname =~ $HOSTNAME_RE;

    push @ids, @{$self->{'config'}->{'opendmarc_trusted_authserv_ids'}};
    my %seen;
    grep { !$seen{lc $_}++ } @ids;
}

=item renderConfBlock( \@trustedIds )

 Render the managed opendmarc.conf(5) block

 Param arrayref \@trustedIds Trusted authserv-ids
 Return string

=cut

sub renderConfBlock
{
    my ($self, $trustedIds) = @_;

    my $c = $self->{'config'};
    my $rejectFailures = "$c->{'opendmarc_reject_failures'}" =~ /^(?:1|true)\z/ ? 'true' : 'false';
    my $trusted = join ',', @{$trustedIds};

    for ( $c->{'opendmarc_authserv_id'}, $trusted, $c->{'opendmarc_socket'}, $c->{'opendmarc_user'} ) {
        # Last line of defense against configuration injection
        /^[^\s"'\\#]+\z/ or die( 'Invalid value for the OpenDMARC configuration file' );
    }

    <<"EOF";
# Begin Plugin::OpenDMARC
# Settings below are managed by the i-MSCP OpenDMARC plugin.
# Overridden distribution settings are commented out with the '$CONF_COMMENT_MARKER' prefix
# and restored when the plugin is deactivated.
AuthservID                  $c->{'opendmarc_authserv_id'}
TrustedAuthservIDs          $trusted
FailureReports              false
IgnoreAuthenticatedClients  true
IgnoreHosts                 $IGNORE_HOSTS_FILE
PidFile                     /run/opendmarc/opendmarc.pid
PublicSuffixList            $PUBLIC_SUFFIX_LIST
RejectFailures              $rejectFailures
RequiredHeaders             false
Socket                      $c->{'opendmarc_socket'}
SoftwareHeader              false
SPFIgnoreResults            true
SPFSelfValidate             true
Syslog                      true
UMask                       0117
UserID                      $c->{'opendmarc_user'}
# Ending Plugin::OpenDMARC
EOF
}

=item updateConfContent( $content, $action [, $block ] )

 Update the given opendmarc.conf(5) content

 Param string $content Current file content
 Param string $action configure|deconfigure
 Param string $block Managed block (configure only)
 Return string

=cut

sub updateConfContent
{
    my (undef, $content, $action, $block) = @_;

    # Remove our configuration block and restore distribution settings
    $content = replaceBloc( $BLOC_BEGIN, $BLOC_END, '', $content );
    $content =~ s/^\Q$CONF_COMMENT_MARKER\E//gm;

    return $content unless $action eq 'configure';

    # Comment out distribution settings that we override. Duplicate keys are a
    # source of confusion as only one of them is honored.
    my $keysRe = join '|', map { quotemeta } @MANAGED_CONF_KEYS;
    $content =~ s/^([\t ]*(?:$keysRe)(?:[\t ]|$))/$CONF_COMMENT_MARKER$1/gim;
    $content .= "\n" if length $content && $content !~ /\n\z/;
    $content . $block;
}

=item _opendmarcSetup( $action )

 Configure or deconfigure OpenDMARC

 Param string $action Action to be performed (configure|deconfigure)
 Return void, die on failure

=cut

sub _opendmarcSetup
{
    my ($self, $action) = @_;

    defined $action && grep ($_ eq $action, 'configure', 'deconfigure') or die( 'Missing or invalid $action parameter' );

    my $c = $self->{'config'};
    my $queueDir = $self->_getQueueDir();

    if ( $action eq 'configure' ) {
        my $socketDir = $self->_getSocketDir( $c->{'opendmarc_socket'} );
        defined $socketDir or die( "Couldn't determine the OpenDMARC socket directory" );
        # The socket directory must be writable by the opendmarc user (the
        # systemd unit runs opendmarc(8) as that user). Its parent must be
        # root-owned (checked by _secureDir()).
        debug( "Creating/Securing the $socketDir OpenDMARC socket directory" );
        _secureDir( $socketDir, $c->{'opendmarc_user'}, $c->{'opendmarc_group'}, 0750 );

        debug( "Creating/Securing the $CONF_DIR directory" );
        _secureDir( $CONF_DIR, 0, 0, 0755 );
        _writeFileAtomic( $IGNORE_HOSTS_FILE, join( "\n", $self->_buildIgnoreHosts()) . "\n", 0, 0, 0644 );
    } elsif ( grep ( $_ eq $self->{'action'}, 'disable', 'uninstall' ) ) {
        debug( 'Stopping/Disabling OpenDMARC service' );
        my $serviceMngr = iMSCP::Service->getInstance();
        if ( $serviceMngr->hasService( 'opendmarc' ) ) {
            $serviceMngr->stop( 'opendmarc' );
            $serviceMngr->disable( 'opendmarc' );
        }

        my $socketDir = $self->_getSocketDir( $self->{'config_prev'}->{'opendmarc_socket'} );
        if ( defined $socketDir && index( $socketDir, "$queueDir/" ) == 0 && lstat $socketDir && -d _ && !-l _ ) {
            debug( "Removing $socketDir OpenDMARC socket directory" );
            iMSCP::Dir->new( dirname => $socketDir )->remove();
        }
    }

    # /etc/opendmarc.conf
    my $fContent = '';
    if ( lstat $CONF_FILE ) {
        die( sprintf( 'Refusing to process %s: not a regular file (symlink?)', $CONF_FILE )) if -l _ || !-f _;
        $fContent = iMSCP::File->new( filename => $CONF_FILE )->get();
        defined $fContent or die( sprintf( "Couldn't read %s file", $CONF_FILE ));
    } elsif ( $action eq 'deconfigure' ) {
        return;
    }

    $fContent = $self->updateConfContent(
        $fContent, $action, $action eq 'configure' ? $self->renderConfBlock( [ $self->_buildTrustedAuthservIds() ] ) : undef
    );
    debug( 'Updating OpenDMARC configuration' );
    _writeFileAtomic( $CONF_FILE, $fContent, 0, 0, 0644 );

    return unless $action eq 'configure';

    # Check the configuration before (re)starting the service
    my ($stdout, $stderr);
    execute( [ $OPENDMARC_BIN, '-n', '-c', $CONF_FILE ], \$stdout, \$stderr ) == 0 or die(
        sprintf( 'Invalid OpenDMARC configuration: %s', $stderr || $stdout || 'Unknown error' )
    );

    my $serviceTasksSub = sub {
        local $@;
        eval {
            debug( 'Enabling/Restarting OpenDMARC service' );
            my $serviceMngr = iMSCP::Service->getInstance();
            $serviceMngr->enable( 'opendmarc' );
            $serviceMngr->restart( 'opendmarc' );
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
                unshift @{$_[0]}, [ $serviceTasksSub, 'OpenDMARC' ];
                0;
            }
        ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
        return;
    }

    $serviceTasksSub->() == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
}

=item _milterRegexps( )

 Get regexps matching the OpenDMARC milter entries (previous and current
 socket, plain or per-milter settings form)

 Return list

=cut

sub _milterRegexps
{
    my ($self) = @_;

    my %sockets = map { $_ => 1 } grep { defined } (
        $self->{'config_prev'}->{'postfix_milter_socket'}, $self->{'config'}->{'postfix_milter_socket'}
    );
    map { qr/^(?:\{\s*)?\Q$_\E(?:\s*[,}].*)?$/s } keys %sockets;
}

# Matches the OpenDKIM milter entry (plain or per-milter settings form)
our $OPENDKIM_MILTER_RE = qr/(?:\{\s*)?(?:unix|local):\S*opendkim\S*?(?:\s*[,}].*)?/s;

=item _postfixSetup( $action )

 Configure or deconfigure Postfix

 Only the OpenDMARC milter is added/removed in the smtpd_milters parameter
 (also removed from non_smtpd_milters, where it is never added: locally
 submitted mail isn't evaluated). Milters from other components (OpenDKIM,
 ClamAV, SpamAssassin...) are left untouched. The OpenDMARC milter is placed
 right after the OpenDKIM milter, as it consumes the DKIM results (A-R
 header field added by OpenDKIM).

 Param string $action Action to perform (configure|deconfigure)
 Return void, die on failure

=cut

sub _postfixSetup
{
    my ($self, $action) = @_;

    defined $action && grep ($_ eq $action, 'configure', 'deconfigure') or die( 'Missing or invalid $action parameter' );

    my $mta = Servers::mta->factory();

    debug( 'Removing OpenDMARC milter from Postfix configuration' );
    my @milterPrevValues = $self->_milterRegexps();
    $mta->postconf(
        smtpd_milters     => { action => 'remove', values => [ @milterPrevValues ] },
        non_smtpd_milters => { action => 'remove', values => [ @milterPrevValues ] }
    ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );

    if ( $action eq 'deconfigure' ) {
        if ( grep ( $_ eq $self->{'action'}, 'disable', 'uninstall' ) && getgrnam( $self->{'config_prev'}->{'opendmarc_group'} ) ) {
            iMSCP::SystemUser->new()->removeFromGroup(
                $self->{'config_prev'}->{'opendmarc_group'}, $mta->{'config'}->{'POSTFIX_USER'}
            ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
        }

        return if defined $main::execmode && $main::execmode eq 'setup';
        return unless $self->{'action'} eq 'disable';

        # On deactivation, reload postfix immediately as the OpenDMARC
        # service becomes unavailable
        $mta->reload() == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
        return;
    }

    # Make the Postfix user able to connect to the OpenDMARC UNIX socket
    iMSCP::SystemUser->new()->addToGroup(
        $self->{'config'}->{'opendmarc_group'}, $mta->{'config'}->{'POSTFIX_USER'}
    ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );

    debug( 'Adding OpenDMARC milter in Postfix configuration' );
    $mta->postconf(
        smtpd_milters => { action => 'add', values => [ $self->_milterEntry() ], after => $OPENDKIM_MILTER_RE }
    ) == 0 or die( getMessageByType( 'error', { amount => 1, remove => 1 } ) || 'Unknown error' );
}

=item _milterEntry( )

 Get the OpenDMARC milter entry (per-milter settings form)

 Return string

=cut

sub _milterEntry
{
    my ($self) = @_;

    "{ $self->{'config'}->{'postfix_milter_socket'}, default_action=$self->{'config'}->{'postfix_milter_default_action'} }";
}

=item splitMilters( $value )

 Split the given milter list (Postfix parameter value)

 Param string $value
 Return list

=cut

sub splitMilters
{
    my (undef, $value) = @_;

    grep { defined && length } extract_multiple(
        $value // '', [ sub { extract_bracketed( $_[0], '{}' ) }, qr/([^,\s]+)/ ], undef, 1
    );
}

=item _checkMilterOrder( )

 Make sure that the OpenDMARC milter is registered after the OpenDKIM milter

 The OpenDKIM plugin (re)appends its milter when it is (re)activated, which
 would place it after the OpenDMARC milter. Postfix is only reconfigured when
 needed (cheap postconf -h check on each run).

 Return void, die on failure

=cut

sub _checkMilterOrder
{
    my ($self) = @_;

    return if defined $main::execmode && $main::execmode eq 'setup';

    my @milters = $self->splitMilters( $self->_postconfGet( 'smtpd_milters' ));
    my @ourRes = $self->_milterRegexps();
    my ($ourIdx) = grep { my $m = $milters[$_]; grep { $m =~ $_ } @ourRes } 0 .. $#milters;
    my ($dkimIdx) = grep { $milters[$_] =~ /^$OPENDKIM_MILTER_RE$/ } 0 .. $#milters;

    return if defined $ourIdx && ( !defined $dkimIdx || $ourIdx > $dkimIdx );

    debug( 'Fixing OpenDMARC milter position in Postfix configuration' );
    local $self->{'action'} = 'change';
    $self->_postfixSetup( 'configure' );
}

=item _syncEntries( )

 Add missing entries (domains and domain aliases) and schedule deletion of the
 entries that belong to domains and domain aliases being deleted

 This covers domains/aliases added while the plugin was deactivated or
 through any other channel than the GUI events. Ordered domain aliases are
 skipped.

 Return void, die on failure

=cut

sub _syncEntries
{
    my ($self) = @_;

    local $self->{'dbh'}->{'RaiseError'} = 1;

    $self->{'dbh'}->do(
        "
            INSERT IGNORE INTO opendmarc (domain_id, alias_id, domain_name, opendmarc_status)
            SELECT t1.domain_id, NULL, t1.domain_name, 'toadd'
            FROM domain AS t1
            WHERE t1.domain_status <> 'todelete'
            AND NOT EXISTS(SELECT 1 FROM opendmarc AS t2 WHERE t2.domain_id = t1.domain_id AND t2.alias_id IS NULL)
        "
    );
    $self->{'dbh'}->do(
        "
            INSERT IGNORE INTO opendmarc (domain_id, alias_id, domain_name, opendmarc_status)
            SELECT t1.domain_id, t1.alias_id, t1.alias_name, 'toadd'
            FROM domain_aliasses AS t1
            WHERE t1.alias_status NOT IN('todelete', 'ordered')
            AND NOT EXISTS(SELECT 1 FROM opendmarc AS t2 WHERE t2.alias_id = t1.alias_id)
        "
    );
    $self->{'dbh'}->do(
        "
            UPDATE opendmarc AS t1
            JOIN domain AS t2 USING(domain_id)
            LEFT JOIN domain_aliasses AS t3 ON(t3.alias_id = t1.alias_id)
            SET t1.opendmarc_status = 'todelete'
            WHERE t1.opendmarc_status <> 'todelete'
            AND (t2.domain_status = 'todelete' OR t3.alias_status = 'todelete')
        "
    );
}

=item _hasCustomerRecord( \%row )

 Does the customer define its own _dmarc DNS record (custom DNS feature)
 for the given domain or domain alias?

 Param hashref \%row opendmarc table row
 Return bool

=cut

sub _hasCustomerRecord
{
    my ($self, $row) = @_;

    my $names = $self->{'dbh'}->selectcol_arrayref(
        "
            SELECT domain_dns FROM domain_dns
            WHERE domain_id = ? AND alias_id = ? AND owned_by <> ? AND domain_dns_status <> 'todelete'
        ",
        undef, $row->{'domain_id'}, $row->{'alias_id'}, $DNS_OWNER
    );

    my $zone = lc $row->{'domain_name'};
    for my $name ( @{$names} ) {
        ( $name ) = split /\s+/, lc( $name // '' ), 2;
        next unless defined $name;
        $name =~ s/\.$//;
        return 1 if $name eq '_dmarc' || $name eq "_dmarc.$zone";
    }

    0;
}

=item _publish( \%row )

 Publish (add or update) the DMARC DNS record of the given domain or domain alias

 Param hashref \%row opendmarc table row
 Return void, die on failure

=cut

sub _publish
{
    my ($self, $row) = @_;

    my $zone = lc $row->{'domain_name'};
    $zone =~ $DOMAIN_NAME_RE or die( sprintf( 'Invalid domain name: %s', $row->{'domain_name'} ));

    if ( $self->_hasCustomerRecord( $row ) ) {
        warning( sprintf( 'A customer-defined _dmarc DNS record exists for the %s domain. Skipping.', $zone ));
        $self->_unpublish( $row );
        return;
    }

    my $name = "_dmarc $self->{'config'}->{'dmarc_dns_records_ttl'}";
    my $text = '"' . $self->renderRecord( $self->_effectiveParams( $row )) . '"';

    my ($domainStatus) = $self->{'dbh'}->selectrow_array(
        'SELECT domain_status FROM domain WHERE domain_id = ?', undef, $row->{'domain_id'}
    );
    defined $domainStatus or die( sprintf( 'Domain with ID %d not found', $row->{'domain_id'} ));
    my $parentDisabled = grep ( $_ eq $domainStatus, 'disabled', 'todisable' );

    my $records = $self->{'dbh'}->selectall_arrayref(
        '
            SELECT domain_dns_id, domain_dns, domain_text, domain_dns_status
            FROM domain_dns
            WHERE domain_id = ? AND alias_id = ? AND owned_by = ?
            ORDER BY domain_dns_id
        ',
        { Slice => {} }, $row->{'domain_id'}, $row->{'alias_id'}, $DNS_OWNER
    );

    my $keep;
    for my $record ( @{$records} ) {
        if ( !$keep && $record->{'domain_dns'} eq $name && $record->{'domain_text'} eq $text ) {
            $keep = $record;
            next;
        }
        next if $record->{'domain_dns_status'} eq 'todelete';
        $self->{'dbh'}->do(
            "UPDATE domain_dns SET domain_dns_status = 'todelete' WHERE domain_dns_id = ?", undef, $record->{'domain_dns_id'}
        );
    }

    if ( $keep ) {
        my $status = $keep->{'domain_dns_status'};
        my $newStatus;
        if ( $parentDisabled ) {
            $newStatus = 'todisable' unless grep ( $_ eq $status, 'disabled', 'todisable' );
        } elsif ( grep ( $_ eq $status, 'disabled', 'todisable', 'todelete' ) ) {
            $newStatus = 'toenable';
        } elsif ( !grep ( $_ eq $status, 'ok', 'toadd', 'tochange', 'toenable' ) ) {
            # Error status: retry
            $newStatus = 'tochange';
        }

        if ( defined $newStatus ) {
            $self->{'dbh'}->do(
                'UPDATE domain_dns SET domain_dns_status = ? WHERE domain_dns_id = ?', undef, $newStatus,
                $keep->{'domain_dns_id'}
            );
        }
        return;
    }

    debug( "Adding DMARC DNS record for the $zone domain" );
    $self->{'dbh'}->do(
        "
            INSERT INTO domain_dns (
                domain_id, alias_id, domain_dns, domain_class, domain_type, domain_text, owned_by, domain_dns_status
            ) VALUES (
                ?, ?, ?, 'IN', 'TXT', ?, ?, ?
            )
        ",
        undef, $row->{'domain_id'}, $row->{'alias_id'}, $name, $text, $DNS_OWNER, $parentDisabled ? 'disabled' : 'toadd'
    );
}

=item _unpublish( \%row )

 Schedule deletion of the DMARC DNS record(s) of the given domain or domain alias

 Param hashref \%row opendmarc table row
 Return void, die on failure

=cut

sub _unpublish
{
    my ($self, $row) = @_;

    $self->{'dbh'}->do(
        "
            UPDATE domain_dns SET domain_dns_status = 'todelete'
            WHERE domain_id = ? AND alias_id = ? AND owned_by = ? AND domain_dns_status <> 'todelete'
        ",
        undef, $row->{'domain_id'}, $row->{'alias_id'}, $DNS_OWNER
    );
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
 group/others unless the sticky bit is set. The directory itself must not be
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

    -d $parent or die( sprintf( "The %s directory doesn't exist", $parent ));
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

=head1 AUTHOR

 i-MSCP Debian 13 port

=cut

1;
__END__
