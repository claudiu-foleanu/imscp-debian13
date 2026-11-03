=head1 NAME

 Plugin::PolicydWeight

=cut

# i-MSCP PolicydWeight plugin
# Copyright (C) 2015-2018 Laurent Declercq <l.declercq@nuxwin.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

package Plugin::PolicydWeight;

use strict;
use warnings;
use autouse 'iMSCP::Debug' => qw/ debug error /;
use autouse 'iMSCP::Execute' => qw/ execute /;
use autouse 'iMSCP::TemplateParser' => qw/ replaceBloc /;
use Class::Autouse qw/ :nostat iMSCP::File iMSCP::Service Servers::mta /;
use Text::Balanced qw/ extract_multiple extract_bracketed /;
use parent 'Common::SingletonClass';

our $CONF_FILE = '/etc/policyd-weight.conf';
my $BLOC_BEGIN = "## Begin Plugin::PolicydWeight\n";
my $BLOC_END = "## Ending Plugin::PolicydWeight\n";

=head1 DESCRIPTION

 This package provides the backend part of the PolicydWeight plugin.

 Note: Debian 13 (Trixie) is the last Debian release providing the
 policyd-weight package (upstream is dead). Consider migrating to the Postfix
 postscreen(8) service.

=head1 PUBLIC METHODS

=over 4

=item enable( )

 Perform enable tasks

 Return 0 on success, other on failure

=cut

sub enable
{
    my ($self) = @_;

    unless ( defined $main::execmode && $main::execmode eq 'setup' || !grep ( $_ eq $self->{'action'}, 'install', 'update' ) ) {
        my $rs = $self->_installDistributionPackages();
        return $rs if $rs;
    }

    my $rs = $self->_configurePolicydWeight( 'configure' );
    return $rs if $rs;

    # The policy service must be evaluated after reject_unauth_destination
    # (see _updateRecipientRestrictions())
    $rs = $self->_updateRecipientRestrictions(
        [ $self->_getPolicyService( $self->{'config_prev'} ) ], $self->_getPolicyService( $self->{'config'} )
    );
    return $rs if $rs;

    $rs = $self->_configureSystemdUnit( 'configure' );
    return $rs if $rs;

    my $serviceTasksSub = sub {
        local $@;
        eval {
            my $serviceMngr = iMSCP::Service->getInstance();
            $serviceMngr->enable( 'policyd-weight' );
            $serviceMngr->restart( 'policyd-weight' );
        };
        if ( $@ ) {
            error( $@ );
            return 1;
        }
        0;
    };

    if ( defined $main::execmode && $main::execmode eq 'setup' ) {
        return $self->{'eventManager'}->register(
            'beforeSetupRestartServices',
            sub {
                unshift @{$_[0]}, [ $serviceTasksSub, 'PolicydWeight' ];
                0;
            }
        );
    }

    $serviceTasksSub->();
}

=item disable( )

 Perform disable tasks

 Return 0 on success, other on failure

=cut

sub disable
{
    my ($self) = @_;

    return 0 if defined $main::execmode && $main::execmode eq 'setup';

    my $rs = $self->_updateRecipientRestrictions( [ $self->_getPolicyService( $self->{'config_prev'} ) ] );
    return $rs if $rs || $self->{'action'} ne 'disable';

    $rs = $self->_configurePolicydWeight( 'deconfigure' );
    return $rs if $rs;

    local $@;
    eval {
        my $serviceMngr = iMSCP::Service->getInstance();
        if ( $serviceMngr->hasService( 'policyd-weight' ) ) {
            $serviceMngr->stop( 'policyd-weight' );
            $serviceMngr->disable( 'policyd-weight' );
        }
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    $self->_configureSystemdUnit( 'deconfigure' );
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 Initialize instance

 Return Plugin::PolicydWeight, die on failure

=cut

sub _init
{
    my ($self) = @_;

    $self->{'config_prev'} ||= {};
    # policyd_weight_host was added in version 1.3.0
    $self->{'config'}->{'policyd_weight_host'} //= '127.0.0.1';
    $self->{'config_prev'}->{'policyd_weight_host'} //= '127.0.0.1';

    for my $param ( qw/ policyd_weight_host policyd_weight_port dnsbl_score rhsbl_score / ) {
        defined $self->{'config'}->{$param} or die( sprintf( "Missing or undefined `%s' plugin configuration parameter", $param ));
        $self->{'config_prev'}->{$param} //= $self->{'config'}->{$param};
    }

    $self->{'config'}->{'policyd_weight_host'} =~ /^(?:[0-9.]+|[0-9a-f:]+)$/i or die(
        "Invalid `policyd_weight_host' plugin configuration parameter. IP address expected."
    );
    $self->{'config'}->{'policyd_weight_port'} =~ /^\d+$/ && $self->{'config'}->{'policyd_weight_port'} < 65536 or die(
        "Invalid `policyd_weight_port' plugin configuration parameter."
    );

    for my $param ( qw/ dnsbl_score rhsbl_score / ) {
        ref $self->{'config'}->{$param} eq 'ARRAY' or die(
            sprintf( "Invalid `%s' plugin configuration parameter. Array expected.", $param )
        );

        for my $entry ( @{$self->{'config'}->{$param}} ) {
            ref $entry eq 'ARRAY' && @{$entry} == 4
                && $entry->[0] =~ /^[a-z0-9.-]+$/i
                && $entry->[1] =~ /^-?\d+(?:\.\d+)?$/
                && $entry->[2] =~ /^-?\d+(?:\.\d+)?$/
                && $entry->[3] =~ /^[A-Z0-9_]+$/i or die( sprintf(
                "Invalid entry in the `%s' plugin configuration parameter. [ 'zone', hit_score, miss_score, 'LOG_NAME' ] expected.",
                $param
            ));
        }
    }

    $self;
}

=item _getPolicyService( \%config )

 Get the policy service for the given configuration

 Param hashref \%config Plugin configuration
 Return string Policy service (inet:<host>:<port>)

=cut

sub _getPolicyService
{
    my (undef, $config) = @_;

    "inet:$config->{'policyd_weight_host'}:$config->{'policyd_weight_port'}";
}

=item _updateRecipientRestrictions( \@servicesToRemove [, $serviceToAdd ] )

 Remove/add check_policy_service restrictions in smtpd_recipient_restrictions

 The Servers::mta::postfix::postconf() helper splits parameter values on
 whitespaces, hence it can neither match nor deduplicate restrictions that
 take an argument, such as 'check_policy_service <service>'. This method
 handles restriction/argument pairs properly. Other restrictions are kept
 untouched (and in the same order).

 The service to add is inserted right before the last 'permit' restriction
 (i-MSCP default restrictions end with '... reject_unauth_destination,
 reject_unlisted_recipient, permit'), hence after reject_unauth_destination,
 else the system could become an open relay. If there is no final 'permit',
 the restriction is appended.

 Param arrayref \@servicesToRemove Policy services to remove (e.g. unix:private/policyd-spf)
 Param string $serviceToAdd OPTIONAL Policy service to add
 Return int 0 on success, other on failure

=cut

sub _updateRecipientRestrictions
{
    my ($self, $servicesToRemove, $serviceToAdd) = @_;

    my $mta = Servers::mta->factory();
    my $confDir = $mta->{'config'}->{'POSTFIX_CONF_DIR'} || '/etc/postfix';

    my $rs = execute( [ 'postconf', '-c', $confDir, '-h', 'smtpd_recipient_restrictions' ], \my $stdout, \my $stderr );
    error( $stderr || 'Unknown error' ) if $rs;
    return $rs if $rs;

    chomp( $stdout //= '' );
    my @tokens = extract_multiple( $stdout, [ sub { extract_bracketed( $_[0], '{}' ) }, qr/([^,\s]+)/ ], undef, 1 );
    my %remove = map { $_ => 1 } grep { defined } @{$servicesToRemove}, $serviceToAdd;
    my ( @restrictions, $removed );

    for ( my $i = 0; $i < @tokens; $i++ ) {
        if ( $tokens[$i] eq 'check_policy_service' && defined $tokens[$i+1] ) {
            my $arg = $tokens[++$i];
            if ( $remove{$arg} ) {
                $removed++;
                next;
            }

            push @restrictions, "check_policy_service $arg";
            next;
        }

        push @restrictions, $tokens[$i];
    }

    if ( defined $serviceToAdd ) {
        my ($idx) = grep { $restrictions[$_] eq 'permit' } reverse 0 .. $#restrictions;
        defined $idx
            ? splice( @restrictions, $idx, 0, "check_policy_service $serviceToAdd" )
            : push( @restrictions, "check_policy_service $serviceToAdd" );
    }

    return 0 unless $removed || defined $serviceToAdd;

    my $value = join ', ', @restrictions;

    $rs = execute( [ 'postconf', '-c', $confDir, '-e', "smtpd_recipient_restrictions=$value" ], \$stdout, \$stderr );
    debug( $stdout ) if $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $mta->{'reload'} = 1 unless $rs;
    $rs;
}

=item _configureSystemdUnit( $action )

 Configure or deconfigure the policyd-weight systemd unit

 The Debian policyd-weight unit (Debian >= 12) runs "policyd-weight -D
 $DAEMON_OPTS" without the 'start' action, making the daemon exit immediately
 (and Postfix defer all mails as the policy service is unreachable). A drop-in
 file makes the unit run policyd-weight as a forking daemon.

 Param string $action Action to perform (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configureSystemdUnit
{
    my ($self, $action) = @_;

    my $dropInDir = '/etc/systemd/system/policyd-weight.service.d';
    my $dropInFile = "$dropInDir/imscp.conf";

    return 0 unless -d '/run/systemd/system';

    if ( $action eq 'configure' ) {
        unless ( -d $dropInDir ) {
            mkdir $dropInDir, 0755 or do {
                error( sprintf( "Couldn't create the %s directory: %s", $dropInDir, $! ));
                return 1;
            };
        }

        my $file = iMSCP::File->new( filename => $dropInFile );
        $file->set( <<'EOT' );
# Drop-in file for the policyd-weight service - auto-generated by the i-MSCP
# PolicydWeight plugin.
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
#
# The Debian unit runs "policyd-weight -D $DAEMON_OPTS" without the 'start'
# action, so the daemon exits immediately. Run it as a forking daemon instead.
[Service]
Type=forking
PIDFile=/run/policyd-weight.pid
ExecStart=
ExecStart=/usr/sbin/policyd-weight start
ExecStop=
ExecStop=/usr/sbin/policyd-weight -k stop
ExecReload=
ExecReload=/usr/sbin/policyd-weight reload
EOT
        my $rs = $file->save();
        $rs ||= $file->mode( 0644 );
        return $rs if $rs;
    } elsif ( -f $dropInFile ) {
        my $rs = iMSCP::File->new( filename => $dropInFile )->delFile();
        return $rs if $rs;
        rmdir $dropInDir;
    } else {
        return 0;
    }

    my $rs = execute( [ 'systemctl', 'daemon-reload' ], \my $stdout, \my $stderr );
    debug( $stdout ) if length $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $rs;
}

=item _configurePolicydWeight( $action )

 Configure or deconfigure policyd-weight (/etc/policyd-weight.conf)

 The plugin manages a block at the end of the configuration file, which
 overrides the default values (policyd-weight evaluates the file as Perl code,
 hence the last assignment wins). Other settings can be added by the
 administrator outside of the block.

 Param string $action Action to perform (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configurePolicydWeight
{
    my ($self, $action) = @_;

    my $file = iMSCP::File->new( filename => $CONF_FILE );
    my $fileContent;

    if ( -f $CONF_FILE ) {
        $fileContent = $file->get();
        unless ( defined $fileContent ) {
            error( sprintf( "Couldn't read %s file", $CONF_FILE ));
            return 1;
        }
    } elsif ( $action eq 'configure' ) {
        $fileContent = "# policyd-weight configuration file -- see policyd-weight.conf(5)\n"
            . "#\n"
            . "# Default values can be printed with: /usr/sbin/policyd-weight defaults\n"
            . "# NOTE: Perl syntax, inclusive `;'. Don't use `my' for overridden variables.\n"
            . "#\n"
            . "# Settings in the block below are managed by the i-MSCP PolicydWeight plugin.\n\n";
    } else {
        return 0;
    }

    $fileContent = replaceBloc( $BLOC_BEGIN, $BLOC_END, '', $fileContent );

    if ( $action eq 'configure' ) {
        my $fmtList = sub {
            join '', map { sprintf( "    '%s', %s, %s, '%s',\n", @{$_} ) } @{$_[0]};
        };

        $fileContent .= $BLOC_BEGIN
            . "# Managed by the i-MSCP PolicydWeight plugin. Don't edit this block; edit the plugin configuration instead.\n"
            . "\$BIND_ADDRESS = '$self->{'config'}->{'policyd_weight_host'}';\n"
            . "\$TCP_PORT = $self->{'config'}->{'policyd_weight_port'};\n"
            . "\@dnsbl_score = (\n#   HOST, HIT SCORE, MISS SCORE, LOG NAME\n"
            . $fmtList->( $self->{'config'}->{'dnsbl_score'} ) . ");\n"
            . "\@rhsbl_score = (\n#   HOST, HIT SCORE, MISS SCORE, LOG NAME\n"
            . $fmtList->( $self->{'config'}->{'rhsbl_score'} ) . ");\n"
            . $BLOC_END;
    }

    $file->set( $fileContent );
    my $rs = $file->save();
    # Must not be world writable, else policyd-weight ignores it
    $rs ||= $file->mode( 0644 );
    $rs ||= $file->owner( $main::imscpConfig{'ROOT_USER'} // 'root', $main::imscpConfig{'ROOT_GROUP'} // 'root' );
    $rs;
}

=item _installDistributionPackages( )

 Install required distribution packages (non-interactive)

 Return int 0 on success, other on failure

=cut

sub _installDistributionPackages
{
    local $ENV{'DEBIAN_FRONTEND'} = 'noninteractive';

    my $rs = execute( [ 'apt-get', 'update' ], \my $stdout, \my $stderr );
    debug( $stdout ) if $stdout;
    error( sprintf( "Couldn't update APT index: %s", $stderr || 'Unknown error' )) if $rs;
    return $rs if $rs;

    $rs = execute(
        [
            'apt-get', '-o', 'DPkg::Options::=--force-confold', '-o', 'DPkg::Options::=--force-confdef',
            '-o', 'DPkg::Options::=--force-confmiss', '--assume-yes', '--no-install-recommends', '--quiet',
            'install', 'policyd-weight'
        ],
        \$stdout,
        \$stderr
    );
    debug( $stdout ) if $stdout;
    error( sprintf( "Couldn't install distribution packages: %s", $stderr || 'Unknown error' )) if $rs;
    $rs;
}

=back

=head1 AUTHOR

 Laurent Declercq <l.declercq@nuxwin.com>

=cut

1;
__END__
