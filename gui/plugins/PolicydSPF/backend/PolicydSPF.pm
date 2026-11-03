=head1 NAME

 Plugin::PolicydSPF

=cut

# i-MSCP PolicydSPF plugin
# @copyright (C) 2016-2017 Laurent Declercq <l.declercq@nuxwin.com>
# @copyright 2016 Ninos Ego <me@ninosego.de>
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

package Plugin::PolicydSPF;

use strict;
use warnings;
use autouse 'iMSCP::Debug' => qw/ debug error getMessageByType /;
use autouse 'iMSCP::Execute' => qw/ execute /;
use autouse 'iMSCP::TemplateParser' => qw/ getBloc replaceBloc /;
use Class::Autouse qw/ :nostat iMSCP::File Servers::mta /;
use Text::Balanced qw/ extract_multiple extract_bracketed /;
use parent 'Common::SingletonClass';

my $BLOC_BEGIN = "# Plugin::PolicydSPF - Begin\n";
my $BLOC_END = "# Plugin::PolicydSPF - Ending\n";
our $POLICYD_SPF_BIN = '/usr/bin/policyd-spf';

=head1 DESCRIPTION

 This package provides the backend part of the PolicydSPF plugin.

 It hooks the postfix-policyd-spf-python policy server (/usr/bin/policyd-spf,
 configuration in /etc/postfix-policyd-spf-python/policyd-spf.conf) into
 Postfix as a spawn(8) service, and adds a check_policy_service restriction in
 the smtpd_recipient_restrictions parameter (after reject_unauth_destination).

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

    $self->_configurePostfix( 'configure' );
}

=item disable( )

 Perform disable tasks

 Return 0 on success, other on failure

=cut

sub disable
{
    my ($self) = @_;

    return 0 if defined $main::execmode && $main::execmode eq 'setup';

    $self->_configurePostfix( 'deconfigure' );
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 Initialize instance

 Return Plugin::PolicydSPF, die on failure

=cut

sub _init
{
    my ($self) = @_;

    $self->{'config_prev'} ||= {};

    for my $param ( qw/ policyd_spf_service policyd_spf_time_limit policyd_spf_user / ) {
        defined $self->{'config'}->{$param} or die( sprintf( "Missing or undefined `%s' plugin configuration parameter", $param ));
        $self->{'config_prev'}->{$param} //= $self->{'config'}->{$param};
    }

    $self->_getServiceName( $self->{'config'}->{'policyd_spf_service'} ) or die(
        "Invalid `policyd_spf_service' plugin configuration parameter. Expected: unix:private/<name>"
    );
    $self->{'config'}->{'policyd_spf_time_limit'} =~ /^\d+[smhdw]?$/ or die(
        "Invalid `policyd_spf_time_limit' plugin configuration parameter."
    );
    $self->{'config'}->{'policyd_spf_user'} =~ /^[a-z_][a-z0-9_-]*$/ or die(
        "Invalid `policyd_spf_user' plugin configuration parameter."
    );

    $self;
}

=item _getServiceName( $service )

 Get Postfix master.cf service name from the given policy service specification

 Param string $service Policy service (unix:private/<name>)
 Return string|undef Service name, undef if the specification is not valid

=cut

sub _getServiceName
{
    my (undef, $service) = @_;

    return unless defined $service && $service =~ m%^unix:private/([a-z0-9][a-z0-9_-]*)$%i;
    $1;
}

=item _configurePostfix( [ $action = 'deconfigure' ] )

 Configure Postfix

 Param string $action Action to perform (configure|deconfigure)
 Return int 0 on success, other on failure

=cut

sub _configurePostfix
{
    my ($self, $action) = @_;
    $action //= 'deconfigure';

    my $mta = Servers::mta->factory();

    # Remove our check_policy_service restrictions (current, previous and
    # legacy policy-spf service) and time limit parameters
    my %services = map { $_ => 1 } grep { defined } (
        $self->{'config_prev'}->{'policyd_spf_service'}, $self->{'config'}->{'policyd_spf_service'}, 'unix:private/policy-spf'
    );

    my $rs = $self->_updateRecipientRestrictions( [ keys %services ] );
    return $rs if $rs;

    my @timeLimitParams = grep { defined } map { $self->_getServiceName( $_ ) } keys %services;
    $_ .= '_time_limit' for @timeLimitParams;
    $rs = $self->_postconfDelete( @timeLimitParams );
    return $rs if $rs;

    my $file = iMSCP::File->new( filename => $mta->{'config'}->{'POSTFIX_MASTER_CONF_FILE'} );
    my $fileContent = $file->get();
    unless ( defined $fileContent ) {
        error( sprintf( "Couldn't read %s file", $file->{'filename'} ));
        return 1;
    }

    $fileContent = replaceBloc( $BLOC_BEGIN, $BLOC_END, '', $fileContent );

    if ( $action eq 'configure' ) {
        unless ( -x $POLICYD_SPF_BIN ) {
            error( "The $POLICYD_SPF_BIN program has not been found. Is the postfix-policyd-spf-python package installed?" );
            return 1;
        }

        my $serviceName = $self->_getServiceName( $self->{'config'}->{'policyd_spf_service'} );
        $fileContent .= $BLOC_BEGIN
            . "$serviceName  unix  -       n       n       -       0       spawn\n"
            . "  user=$self->{'config'}->{'policyd_spf_user'} argv=$POLICYD_SPF_BIN\n"
            . $BLOC_END;
    }

    $file->set( $fileContent );
    $rs = $file->save();
    return $rs if $rs || $action ne 'configure';

    # The policy service must be evaluated after reject_unauth_destination,
    # else the system could become an open relay (see _updateRecipientRestrictions())
    $rs = $self->_updateRecipientRestrictions( [], $self->{'config'}->{'policyd_spf_service'} );
    $rs ||= $self->_postconfSet(
        $self->_getServiceName( $self->{'config'}->{'policyd_spf_service'} ) . '_time_limit',
        $self->{'config'}->{'policyd_spf_time_limit'}
    );
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

=item _postconfSet( $param, $value )

 Set the given Postfix main.cf parameter

 POSTCONF(1) is called directly because service-derived parameters such as
 <service>_time_limit are only known when the service exists in master.cf.

 Param string $param Parameter name
 Param string $value Parameter value
 Return int 0 on success, other on failure

=cut

sub _postconfSet
{
    my ($self, $param, $value) = @_;

    my $mta = Servers::mta->factory();
    my $rs = execute(
        [ 'postconf', '-c', $mta->{'config'}->{'POSTFIX_CONF_DIR'} || '/etc/postfix', '-e', "$param=$value" ], \my $stdout, \my $stderr
    );
    debug( $stdout ) if $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $mta->{'reload'} = 1 unless $rs;
    $rs;
}

=item _postconfDelete( @params )

 Delete the given Postfix main.cf parameters if they exist

 Param list @params Parameter names
 Return int 0 on success, other on failure

=cut

sub _postconfDelete
{
    my ($self, @params) = @_;

    return 0 unless @params;

    my $mta = Servers::mta->factory();
    my $confFile = $mta->{'config'}->{'POSTFIX_CONF_FILE'} || '/etc/postfix/main.cf';
    my $fileContent = iMSCP::File->new( filename => $confFile )->get();
    unless ( defined $fileContent ) {
        error( sprintf( "Couldn't read %s file", $confFile ));
        return 1;
    }

    @params = grep { $fileContent =~ /^\Q$_\E\s*=/m } @params;
    return 0 unless @params;

    my $rs = execute(
        [ 'postconf', '-c', $mta->{'config'}->{'POSTFIX_CONF_DIR'} || '/etc/postfix', '-X', @params ], \my $stdout, \my $stderr
    );
    debug( $stdout ) if $stdout;
    error( $stderr || 'Unknown error' ) if $rs;
    $mta->{'reload'} = 1 unless $rs;
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
            'install', 'postfix-policyd-spf-python'
        ],
        \$stdout,
        \$stderr
    );
    debug( $stdout ) if $stdout;
    error( sprintf( "Couldn't install distribution packages: %s", $stderr || 'Unknown error' )) if $rs;
    $rs;
}

=back

=head1 AUTHORS

 Laurent Declercq <l.declercq@nuxwin.com>
 Ninos Ego <me@ninosego.de>

=cut

1;
__END__
