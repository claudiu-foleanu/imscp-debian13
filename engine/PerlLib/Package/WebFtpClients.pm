=head1 NAME

 Package::WebFtpClients - Web-based FTP client packages

=cut

# i-MSCP - internet Multi Server Control Panel
# Copyright (C) 2010-2019 by Laurent Declercq <l.declercq@nuxwin.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

package Package::WebFtpClients;

use strict;
use warnings;
use iMSCP::Debug qw/ debug error /;
use iMSCP::File;
use parent 'Package::AbstractPackageCollection';

=head1 DESCRIPTION

 Provide Web-based FTP client packages. 

=head1 PUBLIC METHODS

=over 4

=item getConfVarname( )

 See Package::AbstractPackageCollection::getConfVarname()

=cut

sub getConfVarname
{
    my ( $self ) = @_;

    'WEB_FTP_CLIENT_PACKAGES';
}

=item getOptName( )

 See Package::AbstractPackageCollection::getOptName()

=cut

sub getOptName
{
    my ( $self ) = @_;

    'web_ftp_client_packages';
}

=item getDefaultValues( )

 See Package::AbstractPackageCollection::getDefaultValues()

=cut

sub getDefaultValues
{
    my ( $self ) = @_;

    'ElFinder';
}

=item getPackageHumanName( )

 See Package::AbstractPackageCollection::getPackageHumanName()

=cut

sub getPackageHumanName
{
    my ( $self ) = @_;

    'Web-based FTP clients';
}

=item getDeprecatedPackages( )

 Get deprecated packages

 Deprecated packages are no longer offered, even if their Perl module is still
 provided. The i-MSCP MonstaFTP package is no longer available (sources lost,
 and MonstaFTP <= 2.11 is affected by CVE-2025-34299). It is replaced by the
 ElFinder package.

 Return hash Deprecated package names mapped to replacement package names
             (empty string if there is no replacement)

=cut

sub getDeprecatedPackages
{
    my ( $self ) = @_;

    ( MonstaFTP => 'ElFinder' );
}

=item registerSetupListeners( \%events )

 See Package::AbstractPackageCollection::registerSetupListeners()

 Deprecated packages are replaced by their replacement package in the list of
 selected packages (upgrade from a previous version in which they were
 selected).

=cut

sub registerSetupListeners
{
    my ( $self, $events ) = @_;

    my %deprecated = $self->getDeprecatedPackages();
    my @selected = split ',', ::setupGetQuestion( $self->getConfVarname());

    if ( grep { exists $deprecated{$_} } @selected ) {
        my %seen;
        my @kept = grep { length $_ && !$seen{$_}++ } map {
            exists $deprecated{$_} ? $deprecated{$_} : $_
        } @selected;

        @kept = grep { $_ ne 'No' } @kept if grep { $_ ne 'No' } @kept;

        debug( sprintf(
            'Replacing deprecated %s package(s): %s => %s',
            $self->getPackageHumanName(),
            join( ', ', @selected ),
            @kept ? join( ', ', @kept ) : 'No'
        ));

        ::setupSetQuestion(
            $self->getConfVarname(), @kept ? join( ',', @kept ) : 'No'
        );

        # Remove leftover of the MonstaFTP package (its Nginx configuration
        # file is no longer included, but should not be kept around)
        my $rs = $events->registerOne( 'beforeSetupServersAndPackages', sub {
            return 0 unless -f '/etc/nginx/imscp_monstaftp.conf';
            iMSCP::File->new(
                filename => '/etc/nginx/imscp_monstaftp.conf'
            )->delFile();
        } );
        return $rs if $rs;
    }

    $self->SUPER::registerSetupListeners( $events );
}

=item _dialogForPackages( \%dialog )

 See Package::AbstractPackageCollection::_dialogForPackages()

 Skip the dialog when there is no package available.

=cut

sub _dialogForPackages
{
    my ( $self, $dialog ) = @_;

    unless ( @{ $self->{'PACKAGES'} } ) {
        ::setupSetQuestion( $self->getConfVarname(), 'No' );
        return 20;
    }

    $self->SUPER::_dialogForPackages( $dialog );
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 See Package::AbstractPackageCollection::_init()

=cut

sub _init
{
    my ( $self ) = @_;

    $self->SUPER::_init();

    my %deprecated = $self->getDeprecatedPackages();
    @{ $self->{'PACKAGES'} } = grep { !exists $deprecated{$_} } @{ $self->{'PACKAGES'} };
    $self;
}

=back

=head1 AUTHOR

 Laurent Declercq <l.declercq@nuxwin.com>

=cut

1;
__END__
