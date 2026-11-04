=head1 NAME

 iMSCP::HttpDownload - IPv4-resilient HTTP(S) download helpers

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

package iMSCP::HttpDownload;

use strict;
use warnings;
use iMSCP::Boolean;
use iMSCP::Debug 'debug';
use iMSCP::Execute 'execute';
use iMSCP::ProgramFinder;
use LWP::UserAgent ();
use parent 'Exporter';

our @EXPORT_OK = qw/ httpGet httpGetToFile /;

=head1 DESCRIPTION

 HTTP(S) download helpers that transparently retry over IPv4.

 Some hosts (for instance getcomposer.org) resolve to an IPv6 address while the
 server has no working IPv6 route. In that case LWP fails with a "Network is
 unreachable" error even though IPv4 connectivity is fine. These helpers first
 try LWP (honouring proxy environment variables) and, on a connectivity
 failure, fall back to an external downloader (curl/wget) forced to IPv4.

=head1 PUBLIC FUNCTIONS

=over 4

=item httpGet( $url )

 Fetch $url and return its body as a string, or undef on failure.

=cut

sub httpGet
{
    my ( $url ) = @_;

    my $res = _ua()->get( $url );
    return $res->decoded_content if $res->is_success;

    if ( _isNetworkError( $res->status_line ) ) {
        debug( sprintf( "HTTP GET %s failed (%s); retrying over IPv4", $url, $res->status_line ));
        my $content = _ipv4Fallback( $url, undef );
        return $content if defined $content;
    }

    undef;
}

=item httpGetToFile( $url, $file )

 Fetch $url, storing its body into $file. Return TRUE on success, FALSE otherwise.

=cut

sub httpGetToFile
{
    my ( $url, $file ) = @_;

    my $res = _ua()->get( $url, ':content_file' => $file );
    return TRUE if $res->is_success;

    if ( _isNetworkError( $res->status_line ) ) {
        debug( sprintf( "HTTP GET %s failed (%s); retrying over IPv4", $url, $res->status_line ));
        return TRUE if _ipv4Fallback( $url, $file );
    }

    FALSE;
}

=back

=head1 PRIVATE FUNCTIONS

=over 4

=item _ua( )

 Return a configured LWP::UserAgent instance.

=cut

sub _ua
{
    LWP::UserAgent->new(
        agent     => 'i-MSCP',
        timeout   => 30,
        env_proxy => TRUE
    );
}

=item _isNetworkError( $statusLine )

 Whether the given LWP status line denotes a connectivity failure worth an
 IPv4 retry.

=cut

sub _isNetworkError
{
    my ( $statusLine ) = @_;

    defined $statusLine && $statusLine =~ /
        unreachable
        | timed?\s*out
        | timeout
        | can't\s+connect
        | no\s+route\s+to\s+host
        | connection\s+refused
        | temporary\s+failure\s+in\s+name\s+resolution
    /xi;
}

=item _ipv4Fallback( $url, $file )

 Retry the download over IPv4 using an external downloader (curl, then wget).
 When $file is defined the body is written there and TRUE is returned on
 success; otherwise the body is returned as a string. Returns undef/FALSE when
 no downloader is available or the retry fails.

=cut

sub _ipv4Fallback
{
    my ( $url, $file ) = @_;

    for my $tool ( qw/ curl wget / ) {
        my $bin = iMSCP::ProgramFinder::find( $tool ) or next;

        my @cmd;
        if ( $tool eq 'curl' ) {
            @cmd = ( $bin, '-4', '-fsSL', '--connect-timeout', '30', '--max-time', '120' );
            push @cmd, ( '-o', $file ) if defined $file;
            push @cmd, $url;
        } else {
            @cmd = ( $bin, '-4', '-q', '--timeout=120', '--tries=2' );
            push @cmd, ( defined $file ? ( '-O', $file ) : ( '-O', '-' ) );
            push @cmd, $url;
        }

        next if execute( \@cmd, \my $stdout, \my $stderr ) != 0;
        return defined $file ? TRUE : $stdout;
    }

    defined $file ? FALSE : undef;
}

=back

=head1 AUTHOR

 i-MSCP Team

=cut

1;
__END__
