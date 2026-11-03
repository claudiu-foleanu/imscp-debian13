=head1 NAME

 Plugin::SGW_LetsEncrypt

=cut

# i-MSCP SGW_LetsEncrypt plugin
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

package Plugin::SGW_LetsEncrypt;

use strict;
use warnings;
use File::Basename qw/ basename dirname /;
use File::Spec;
use iMSCP::Boolean;
use iMSCP::Database;
use iMSCP::Debug qw/ debug error warning /;
use iMSCP::Dir;
use iMSCP::Execute qw/ execute /;
use iMSCP::File;
use Socket qw/ getaddrinfo AF_UNSPEC SOCK_STREAM /;
use version;
use parent 'Common::SingletonClass';

# Name of the Apache global configuration file that exposes the shared ACME
# challenge directory for every vhost (conf-available/conf-enabled)
use constant ACME_CONF_NAME => 'imscp_sgw_letsencrypt.conf';

# Name of the certbot deploy hook installed in <config-dir>/renewal-hooks/deploy
use constant DEPLOY_HOOK_NAME => 'imscp-sgw-letsencrypt';

# Statuses of plugin items which are processed by the run() action
use constant PENDING_STATUSES => qw/ toadd tochange todelete /;

=head1 DESCRIPTION

 Backend part of the i-MSCP SGW_LetsEncrypt plugin.

 Certificates are obtained through the Debian certbot package, using the
 webroot authenticator and a single ACME challenge directory that is exposed
 for all vhosts through a global Apache configuration file. Certificates stay
 managed by certbot (/etc/letsencrypt) and are imported into the i-MSCP
 ssl_certs table, so that i-MSCP builds the SSL vhosts natively, whatever the
 httpd server implementation (apache_php_fpm, apache_fcgid, apache_itk).

 Renewal is done by the certbot.timer systemd unit (certbot package). A deploy
 hook installed by this plugin re-imports renewed certificates into i-MSCP and
 reloads Apache.

=head1 PUBLIC METHODS

=over 4

=item install( )

 Perform install tasks

 Return int 0 on success, other on failure

=cut

sub install
{
    my ( $self ) = @_;

    my $rs = $self->_checkRequirements();
    $rs ||= $self->_removeLegacyCronJob();
}

=item uninstall( )

 Perform uninstall tasks

 Note: The GUI part drops the plugin database table before this action is
 run. Lineages created by this plugin are identified through their renewal
 configuration (webroot authenticator using our ACME challenge directory).
 Certificates which were imported into i-MSCP are left in place (they remain
 valid until they expire). Customers should disable Let's Encrypt for their
 domains before the plugin is uninstalled.

 Return int 0 on success, other on failure

=cut

sub uninstall
{
    my ( $self ) = @_;

    my $rs = $self->_deleteAcmeConf();
    $rs ||= $self->_deleteDeployHook();
    return $rs if $rs;

    for my $certName ( $self->_getOwnLineages() ) {
        $self->_certbotDelete( $certName );
    }

    0;
}

=item update( $fromVersion )

 Perform update tasks

 Param string $fromVersion Version from which the plugin is being updated
 Return int 0 on success, other on failure

=cut

sub update
{
    my ( $self, $fromVersion ) = @_;

    my $rs = $self->_checkRequirements();
    $rs ||= $self->_removeLegacyCronJob();
    return $rs if $rs;

    local $@;
    my $version = eval { version->parse( $fromVersion // '0' ) } // version->parse( '0' );

    if ( $version < version->parse( '1.6.0' ) ) {
        # Versions prior 1.6.0 relied on certbot-auto with the apache
        # authenticator and on a self-signed placeholder certificate in the
        # ssl_certs table. Schedule all active certificates for
        # (re)processing. Lineages which are still configured for the apache
        # authenticator are force-renewed through the webroot authenticator
        # and the resulting certificates imported into i-MSCP.
        eval {
            $self->{'dbh'}->do(
                "UPDATE letsencrypt SET status = 'tochange' WHERE status = 'ok'"
            );
            # Pre-1.6.0 GUI created placeholder rows when the edit page was
            # merely viewed. Those rows have no meaning.
            $self->{'dbh'}->do( "DELETE FROM letsencrypt WHERE status = 'disabled'" );
        };
        if ( $@ ) {
            error( $@ );
            return 1;
        }
    }

    0;
}

=item change( )

 Perform change tasks (plugin configuration change)

 Return int 0 on success, other on failure

=cut

sub change
{
    my ( $self ) = @_;

    my $rs = $self->_checkRequirements();
    return $rs if $rs;

    my $changed = FALSE;
    for my $param ( qw/ staging key_type test_mode www hsts_max_age hsts_include_subdomains / ) {
        my $new = $self->{'config'}->{$param} // '';
        my $old = $self->{'config_prev'}->{$param} // '';
        next if "$new" eq "$old";
        $changed = TRUE;
        last;
    }

    return 0 unless $changed;

    # Reprocess active certificates on next run
    local $@;
    eval {
        $self->{'dbh'}->do( "UPDATE letsencrypt SET status = 'tochange' WHERE status = 'ok'" );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item enable( )

 Perform enable tasks

 Return int 0 on success, other on failure

=cut

sub enable
{
    my ( $self ) = @_;

    my $rs = $self->_checkRequirements();
    $rs ||= $self->_createAcmeWebroot();
    $rs ||= $self->_writeAcmeConf();
    $rs ||= $self->_installDeployHook();
}

=item disable( )

 Perform disable tasks

 Note: Once disabled, renewal of the certificates is no longer possible as
 the ACME challenge directory is no longer exposed.

 Return int 0 on success, other on failure

=cut

sub disable
{
    my ( $self ) = @_;

    my $rs = $self->_getHttpd()->disableConfs( ACME_CONF_NAME );
    $rs ||= $self->_deleteDeployHook();
}

=item run( )

 Process plugin items (letsencrypt table)

 Item errors are stored in the item status field. This method only returns
 a non-zero value on unexpected (database) errors, because a non-zero return
 value puts the whole plugin in error state.

 Return int 0 on success, other on failure

=cut

sub run
{
    my ( $self ) = @_;

    # Don't process certificates in setup context (imscp-reconfigure). The
    # httpd service could be stopped, or its configuration being rebuilt.
    return 0 if defined $::execmode && $::execmode eq 'setup';

    my @statuses = PENDING_STATUSES;
    my $rows;
    local $@;
    eval {
        $rows = $self->{'dbh'}->selectall_arrayref(
            "
                SELECT letsencrypt_id, admin_id, domain_id, alias_id, subdomain_id, cert_name, http_forward, status
                FROM letsencrypt
                WHERE status IN(" . join( ', ', ( '?' ) x @statuses ) . ")
                ORDER BY letsencrypt_id ASC
            ",
            { Slice => {} },
            @statuses
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    my $rs = 0;
    for my $row ( @{ $rows } ) {
        $rs = $self->_processItem( $row );
        last if $rs;
    }

    $rs ||= $self->_collectGarbage();
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 Initialize plugin

 Return Plugin::SGW_LetsEncrypt

=cut

sub _init
{
    my ( $self ) = @_;

    $self->{'config'} ||= {};
    $self->{'config_prev'} ||= {};
    $self->{'dbh'} = iMSCP::Database->factory()->getRawDb();
    $self->{'pluginDir'} = "$::imscpConfig{'PLUGINS_DIR'}/SGW_LetsEncrypt";
    $self;
}

=item _getHttpd( )

 Get httpd server instance (lazy loading)

 Return Servers::httpd::apache_*

=cut

sub _getHttpd
{
    my ( $self ) = @_;

    $self->{'httpd'} //= do {
        require Servers::httpd;
        Servers::httpd->factory();
    };
}

=item _isTestMode( )

 Whether the opt-in test mode is enabled (mocked certbot issuing
 certificates from a local test CA)

 Return bool

=cut

sub _isTestMode
{
    $_[0]->{'config'}->{'test_mode'} ? TRUE : FALSE;
}

=item _certbotConfigDir( )

 Get certbot configuration directory

 Return string

=cut

sub _certbotConfigDir
{
    my ( $self ) = @_;

    $self->_isTestMode()
        ? '/var/lib/imscp-sgw-letsencrypt-mock'
        : '/etc/letsencrypt';
}

=item _certbotBaseCmd( )

 Get base certbot command (list form)

 Return array

=cut

sub _certbotBaseCmd
{
    my ( $self ) = @_;

    return ( '/usr/bin/perl', "$self->{'pluginDir'}/backend/certbot-mock.pl",
        '--config-dir', $self->_certbotConfigDir()
    ) if $self->_isTestMode();

    ( $self->{'config'}->{'certbot'} || '/usr/bin/certbot' );
}

=item _webroot( )

 Get the shared ACME webroot directory

 The challenge files are stored by certbot in <webroot>/.well-known/acme-challenge/

 Return string Webroot path, die if the configured value is not safe

=cut

sub _webroot
{
    my ( $self ) = @_;

    my $webroot = $self->{'config'}->{'webroot'} || '/var/www/imscp/acme-challenge';
    $webroot =~ s%/+$%%;

    # Value is used in an Apache configuration file: be strict
    $webroot =~ m%^(?:/[A-Za-z0-9._-]+)+\z% && $webroot !~ m%/\.\.?(?:/|\z)% or die(
        sprintf( 'Invalid webroot path in plugin configuration: %s', $webroot )
    );

    $webroot;
}

=item _checkRequirements( )

 Check for requirements

 Return int 0 if all requirements are met, 1 otherwise

=cut

sub _checkRequirements
{
    my ( $self ) = @_;

    return 0 if $self->_isTestMode();

    my ( $certbot ) = $self->_certbotBaseCmd();
    unless ( -x $certbot ) {
        error( sprintf(
            "The certbot program (%s) is missing. Please install the Debian 'certbot' package.", $certbot
        ));
        return 1;
    }

    0;
}

=item _removeLegacyCronJob( )

 Remove the weekly certbot-auto cron job installed by plugin versions < 1.6.0

 Renewal is now handled by the certbot.timer systemd unit (certbot package)

 Return int 0 on success, other on failure

=cut

sub _removeLegacyCronJob
{
    my $cronFile = '/etc/cron.weekly/letsencrypt';
    return 0 unless -f $cronFile;

    my $content = iMSCP::File->new( filename => $cronFile )->get();
    return 0 unless defined $content
        && index( $content, '/usr/local/bin/certbot-auto renew' ) != -1;

    iMSCP::File->new( filename => $cronFile )->delFile();
}

=item _createAcmeWebroot( )

 Create the shared ACME challenge directory

 Directories must be world readable: with apache_itk, the files are served by
 an Apache process running as the customer user.

 Return int 0 on success, die on failure

=cut

sub _createAcmeWebroot
{
    my ( $self ) = @_;

    my $webroot = $self->_webroot();
    for my $dir ( $webroot, "$webroot/.well-known", "$webroot/.well-known/acme-challenge" ) {
        iMSCP::Dir->new( dirname => $dir )->make( {
            user  => $::imscpConfig{'ROOT_USER'},
            group => $::imscpConfig{'ROOT_GROUP'},
            mode  => 0755
        } );
    }

    0;
}

=item _renderAcmeConf( $webroot )

 Render the Apache configuration exposing the ACME challenge directory

 The Alias directive is declared at server level and therefore inherited by
 every vhost (customer vhosts, forward/proxy vhosts, HTTP->HTTPS redirect
 vhosts and the default vhost). i-MSCP vhost RedirectMatch/ProxyPassMatch
 directives already exclude /.well-known/acme-challenge/, and mod_alias
 processes Redirect* directives before Alias, so the challenge path is never
 redirected. Customer .htaccess files don't apply as the aliased directory is
 outside of the document roots.

 Param string $webroot ACME webroot
 Return string Apache configuration

=cut

sub _renderAcmeConf
{
    my ( undef, $webroot ) = @_;

    <<"EOF";
# Managed by the i-MSCP SGW_LetsEncrypt plugin. DO NOT EDIT.
# Exposes the shared ACME (Let's Encrypt) HTTP-01 challenge directory for all vhosts.
Alias "/.well-known/acme-challenge/" "$webroot/.well-known/acme-challenge/"

<Directory "$webroot/.well-known/acme-challenge">
    Options None
    AllowOverride None
    SetHandler None
    ForceType text/plain
    Require all granted
</Directory>
EOF
}

=item _writeAcmeConf( )

 Write and enable the Apache ACME challenge configuration

 Return int 0 on success, other on failure

=cut

sub _writeAcmeConf
{
    my ( $self ) = @_;

    my $httpd = $self->_getHttpd();
    my $file = iMSCP::File->new(
        filename => "$httpd->{'config'}->{'HTTPD_CONF_DIR'}/conf-available/" . ACME_CONF_NAME
    );
    $file->set( $self->_renderAcmeConf( $self->_webroot()));
    my $rs = $file->save();
    $rs ||= $file->owner( $::imscpConfig{'ROOT_USER'}, $::imscpConfig{'ROOT_GROUP'} );
    $rs ||= $file->mode( 0644 );
    $rs ||= $httpd->enableConfs( ACME_CONF_NAME );
}

=item _deleteAcmeConf( )

 Disable and remove the Apache ACME challenge configuration

 Return int 0 on success, other on failure

=cut

sub _deleteAcmeConf
{
    my ( $self ) = @_;

    my $httpd = $self->_getHttpd();
    my $rs = $httpd->disableConfs( ACME_CONF_NAME );
    return $rs if $rs;

    my $file = "$httpd->{'config'}->{'HTTPD_CONF_DIR'}/conf-available/" . ACME_CONF_NAME;
    return 0 unless -f $file;

    $httpd->{'restart'} = TRUE;
    iMSCP::File->new( filename => $file )->delFile();
}

=item _deployHookPath( )

 Get path of the deploy hook

 Return string

=cut

sub _deployHookPath
{
    my ( $self ) = @_;

    # The certbot mock (test mode) runs the hooks from the real directory too
    '/etc/letsencrypt/renewal-hooks/deploy/' . DEPLOY_HOOK_NAME;
}

=item _renderDeployHook( )

 Render the deploy hook from its template

 Return string|undef Deploy hook content, undef on failure

=cut

sub _renderDeployHook
{
    my ( $self ) = @_;

    my $tpl = iMSCP::File->new( filename => "$self->{'pluginDir'}/backend/deploy-hook.pl" )->get();
    return undef unless defined $tpl;

    my $roots = iMSCP::File->new( filename => "$self->{'pluginDir'}/backend/staging-roots.pem" )->get();
    return undef unless defined $roots;
    $roots =~ s/^#.*\n//mg;
    $roots =~ s/\s+$//;

    my %vars = (
        ENGINE_ROOT_DIR => $::imscpConfig{'ENGINE_ROOT_DIR'},
        STAGING_ROOTS   => $roots
    );

    $tpl =~ s/\{\{([A-Z_]+)\}\}/exists $vars{$1} ? $vars{$1} : "{{$1}}"/ge;
    $tpl;
}

=item _installDeployHook( )

 Install the certbot deploy hook

 Return int 0 on success, other on failure

=cut

sub _installDeployHook
{
    my ( $self ) = @_;

    my $hook = $self->_deployHookPath();

    for my $dir ( '/etc/letsencrypt', '/etc/letsencrypt/renewal-hooks', dirname( $hook ) ) {
        next if -d $dir;
        iMSCP::Dir->new( dirname => $dir )->make( {
            user  => $::imscpConfig{'ROOT_USER'},
            group => $::imscpConfig{'ROOT_GROUP'},
            mode  => 0755
        } );
    }

    my $content = $self->_renderDeployHook();
    return 1 unless defined $content;

    my $file = iMSCP::File->new( filename => $hook );
    $file->set( $content );
    my $rs = $file->save();
    $rs ||= $file->owner( $::imscpConfig{'ROOT_USER'}, $::imscpConfig{'ROOT_GROUP'} );
    $rs ||= $file->mode( 0750 );
}

=item _deleteDeployHook( )

 Remove the certbot deploy hook

 Return int 0 on success, other on failure

=cut

sub _deleteDeployHook
{
    my ( $self ) = @_;

    my $hook = $self->_deployHookPath();
    return 0 unless -f $hook;
    iMSCP::File->new( filename => $hook )->delFile();
}

=item _processItem( \%row )

 Process the given letsencrypt item

 Param hashref \%row Item data
 Return int 0 on success (including item errors), 1 on database error

=cut

sub _processItem
{
    my ( $self, $row ) = @_;

    my ( $type, $id ) = _domainTypeAndId( @{ $row }{qw/ domain_id alias_id subdomain_id /} );

    local $@;
    my $entity = $type ? eval { $self->_getEntity( $type, $id ) } : undef;
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    # Entity doesn't exist anymore, or is being deleted: core removes the
    # ssl_certs entries. We only have to remove the lineage and the item.
    if ( !$entity || $entity->{'status'} eq 'todelete' ) {
        $self->_certbotDelete( $row->{'cert_name'} ) if _isValidDomainName( $row->{'cert_name'} );
        eval { $self->{'dbh'}->do( 'DELETE FROM letsencrypt WHERE letsencrypt_id = ?', undef, $row->{'letsencrypt_id'} ); };
        if ( $@ ) {
            error( $@ );
            return 1;
        }
        return 0;
    }

    my ( $status, $state ) = ( 'ok', '' );
    my $delete = FALSE;

    if ( $row->{'status'} eq 'todelete' ) {
        ( my $error ) = $self->_deleteCertificate( $type, $id, $entity );
        if ( defined $error ) {
            $status = $error;
        } else {
            $delete = TRUE;
        }
    } else {
        ( my $error, $state ) = $self->_addCertificate( $type, $id, $entity, $row->{'http_forward'} );
        $status = $error if defined $error;
    }

    eval {
        if ( $delete ) {
            $self->{'dbh'}->do( 'DELETE FROM letsencrypt WHERE letsencrypt_id = ?', undef, $row->{'letsencrypt_id'} );
        } else {
            $self->{'dbh'}->do(
                'UPDATE letsencrypt SET status = ?, state = ?, cert_name = ? WHERE letsencrypt_id = ?',
                undef, _truncate( $status, 250 ), _truncate( $state // '', 250 ), $entity->{'name'},
                $row->{'letsencrypt_id'}
            );
        }
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    0;
}

=item _domainTypeAndId( $domainId, $aliasId, $subdomainId )

 Get i-MSCP domain type (dmn|als|sub) and identifier for the given item

 For historical reasons, items for domain aliases and subdomains have
 domain_id set to 0.

 Return list ( $type, $id ), ( '', 0 ) if the item is invalid

=cut

sub _domainTypeAndId
{
    my ( $domainId, $aliasId, $subdomainId ) = @_;

    return ( 'als', $aliasId ) if $aliasId;
    return ( 'sub', $subdomainId ) if $subdomainId;
    return ( 'dmn', $domainId ) if $domainId;
    ( '', 0 );
}

=item _getEntity( $type, $id )

 Get the i-MSCP entity (domain, domain alias, subdomain) for the given type and id

 Return hashref|undef { name, status, admin_id } or undef if not found

=cut

sub _getEntity
{
    my ( $self, $type, $id ) = @_;

    my %queries = (
        dmn => '
            SELECT domain_name AS name, domain_status AS status, domain_admin_id AS admin_id
            FROM domain WHERE domain_id = ?
        ',
        als => '
            SELECT t1.alias_name AS name, t1.alias_status AS status, t2.domain_admin_id AS admin_id
            FROM domain_aliasses AS t1 JOIN domain AS t2 USING(domain_id) WHERE t1.alias_id = ?
        ',
        sub => "
            SELECT CONCAT(t1.subdomain_name, '.', t2.domain_name) AS name, t1.subdomain_status AS status,
                t2.domain_admin_id AS admin_id
            FROM subdomain AS t1 JOIN domain AS t2 USING(domain_id) WHERE t1.subdomain_id = ?
        "
    );

    return undef unless $queries{$type};
    $self->{'dbh'}->selectrow_hashref( $queries{$type}, undef, $id );
}

=item _setEntityStatus( $type, $id )

 Schedule rebuild of the given entity (only if its current status is 'ok')

 Return void, die on failure

=cut

sub _setEntityStatus
{
    my ( $self, $type, $id ) = @_;

    my %queries = (
        dmn => "UPDATE domain SET domain_status = 'tochange' WHERE domain_id = ? AND domain_status = 'ok'",
        als => "UPDATE domain_aliasses SET alias_status = 'tochange' WHERE alias_id = ? AND alias_status = 'ok'",
        sub => "UPDATE subdomain SET subdomain_status = 'tochange' WHERE subdomain_id = ? AND subdomain_status = 'ok'"
    );

    $self->{'dbh'}->do( $queries{$type}, undef, $id );
}

=item _addCertificate( $type, $id, \%entity, $httpForward )

 Obtain (or reuse) a Let's Encrypt certificate and import it into i-MSCP

 This action is idempotent: an existing certificate is kept until it is due
 for renewal, unless its renewal configuration is not the expected one.

 Return list ( $error, $note ) where $error is undef on success

=cut

sub _addCertificate
{
    my ( $self, $type, $id, $entity, $httpForward ) = @_;

    my $name = lc $entity->{'name'};
    return ( sprintf( 'Invalid domain name: %s', $name ), '' ) unless _isValidDomainName( $name );

    unless ( $entity->{'status'} =~ /^(?:ok|toadd|tochange|toenable|torestore)$/ ) {
        return ( sprintf( 'The %s domain is not active (status: %s).', $name, _truncate( $entity->{'status'}, 60 )), '' );
    }

    my $httpd = $self->_getHttpd();
    unless ( -e "$httpd->{'config'}->{'HTTPD_CONF_DIR'}/conf-enabled/" . ACME_CONF_NAME ) {
        return ( 'The ACME challenge Apache configuration is not enabled. Please re-enable the plugin.', '' );
    }

    # Domains for which the certificate is requested
    my @domains = ( $name );
    my @notes;
    my $checkDns = $self->{'config'}->{'check_dns'} // TRUE;
    my $wwwPolicy = $self->{'config'}->{'www'} // 'auto';

    if ( !$self->_isTestMode() && $checkDns && !_resolves( $name ) ) {
        return ( sprintf( "The %s domain name doesn't resolve. Let's Encrypt cannot validate it.", $name ), '' );
    }

    if ( index( $name, 'www.' ) == 0 ) {
        # Already a www name: nothing to add
    } elsif ( $wwwPolicy eq 'always' ) {
        push @domains, "www.$name";
    } elsif ( $wwwPolicy eq 'auto' ) {
        if ( $self->_isTestMode() || _resolves( "www.$name" ) ) {
            push @domains, "www.$name";
        } else {
            push @notes, sprintf( "www.%s not included (doesn't resolve)", $name );
        }
    }

    my $renewalConf = $self->_readRenewalConf( $name );
    my $cmd = $self->_buildCertonlyCmd( $name, \@domains, $renewalConf );

    my $rs = execute( $cmd, \my $stdout, \my $stderr );
    debug( $stdout ) if length $stdout;
    if ( $rs ) {
        my $msg = _certbotErrorMessage( $stderr, $stdout ) || "certbot exited with status $rs";
        warning( sprintf( "Couldn't obtain Let's Encrypt certificate for %s: %s", $name, $stderr // '' ));
        return ( "certbot: $msg", join( '; ', @notes ));
    }

    # With --allow-subset-of-names, names which couldn't be validated are
    # silently dropped by certbot.
    if ( my @missing = $self->_getMissingNames( $name, \@domains ) ) {
        push @notes, sprintf( '%s not included (validation failed)', join( ', ', @missing ));
    }

    my $error = $self->_importCertificate( $type, $id, $name, $httpForward );
    return ( $error, join( '; ', @notes )) if defined $error;

    ( undef, join( '; ', @notes ));
}

=item _getMissingNames( $name, \@domains )

 Get the names which are not covered by the current certificate of the given lineage

 Return list Missing names (empty list on error)

=cut

sub _getMissingNames
{
    my ( $self, $name, $domains ) = @_;

    my $cert = $self->_certbotConfigDir() . "/live/$name/cert.pem";
    return () unless -f $cert;

    my $rs = execute(
        [ '/usr/bin/openssl', 'x509', '-in', $cert, '-noout', '-ext', 'subjectAltName' ], \my $stdout, \my $stderr
    );
    return () if $rs;

    my %san = map { lc $_ => 1 } $stdout =~ /DNS:([^,\s]+)/g;
    grep { !$san{$_} } @{ $domains };
}

=item _buildCertonlyCmd( $name, \@domains, \%renewalConf|undef )

 Build the certbot certonly command (list form)

 Param string $name Certificate (lineage) name
 Param arrayref \@domains Domains to include in the certificate
 Param hashref|undef \%renewalConf Current renewal parameters of the lineage, if any
 Return arrayref

=cut

sub _buildCertonlyCmd
{
    my ( $self, $name, $domains, $renewalConf ) = @_;

    my $config = $self->{'config'};
    my $webroot = $self->_webroot();
    my $staging = $config->{'staging'} ? TRUE : FALSE;
    my $keyType = ( $config->{'key_type'} // 'rsa' ) eq 'ecdsa' ? 'ecdsa' : 'rsa';
    my $email = $self->_getAccountEmail();

    my @cmd = (
        $self->_certbotBaseCmd(),
        'certonly',
        '--non-interactive',
        '--agree-tos',
        ( length $email
            ? ( '--email', $email, '--no-eff-email' ) : ( '--register-unsafely-without-email' )
        ),
        '--webroot', '--webroot-path', $webroot,
        '--cert-name', $name,
        ( map { ( '--domain', $_ ) } @{ $domains } ),
        '--key-type', $keyType,
        '--keep-until-expiring',
        ( ( $config->{'allow_subset_of_names'} // TRUE ) ? '--allow-subset-of-names' : () ),
        ( $staging ? ( '--test-cert', '--break-my-certs' ) : () ),
    );

    # Force renewal when the existing lineage doesn't use the expected
    # authenticator/webroot (e.g. legacy certbot-auto lineages configured for
    # the apache authenticator) or ACME server (staging <-> production
    # switch). Without this, certbot would keep the current certificate and
    # its renewal configuration until the certificate is due for renewal.
    if ( $renewalConf ) {
        my $isStaging = ( $renewalConf->{'server'} // '' ) =~ /staging/ ? TRUE : FALSE;
        my @webroots = grep { length } split /\s*,\s*/, $renewalConf->{'webroot_path'} // '';
        if ( ( $renewalConf->{'authenticator'} // '' ) ne 'webroot'
            || !grep ( $_ eq $webroot, @webroots )
            || $isStaging != $staging
        ) {
            push @cmd, '--force-renewal';
        }
    }

    \@cmd;
}

=item _getAccountEmail( )

 Get the ACME account email address

 Order: plugin configuration (email), i-MSCP DEFAULT_ADMIN_ADDRESS, email of
 the first administrator.

 Return string Email or empty string

=cut

sub _getAccountEmail
{
    my ( $self ) = @_;

    for my $email ( $self->{'config'}->{'email'}, $::imscpConfig{'DEFAULT_ADMIN_ADDRESS'} ) {
        return $email if defined $email && _isValidEmail( $email );
    }

    local $@;
    my ( $email ) = eval {
        $self->{'dbh'}->selectrow_array(
            "SELECT email FROM admin WHERE admin_type = 'admin' ORDER BY admin_id ASC LIMIT 1"
        );
    };

    defined $email && _isValidEmail( $email ) ? $email : '';
}

=item _readRenewalConf( $name )

 Read the [renewalparams] section of the renewal configuration for the given lineage

 Return hashref|undef Renewal parameters or undef if there is no such lineage

=cut

sub _readRenewalConf
{
    my ( $self, $name ) = @_;

    my $file = $self->_certbotConfigDir() . "/renewal/$name.conf";
    return undef unless -f $file;

    my $content = iMSCP::File->new( filename => $file )->get();
    return undef unless defined $content;

    _parseRenewalConf( $content );
}

=item _parseRenewalConf( $content )

 Parse renewal configuration (configobj format)

 Return hashref [renewalparams] key/value pairs (subsections are ignored)

=cut

sub _parseRenewalConf
{
    my ( $content ) = @_;

    my %params;
    my $inSection = FALSE;
    for my $line ( split /\n/, $content ) {
        if ( $line =~ /^\s*\[\s*([^\[\]]+?)\s*\]\s*$/ ) {
            $inSection = $1 eq 'renewalparams';
            next;
        }
        next if $line =~ /^\s*\[\[/; # subsection (e.g. [[webroot_map]])
        if ( $inSection && $line =~ /^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/ ) {
            $params{$1} = $2;
        }
    }

    # Subsection lines are matched as key/value pairs above. They are
    # harmless as we only read known keys.
    \%params;
}

=item _getOwnLineages( )

 Get name of lineages managed by this plugin

 A lineage is considered as managed by this plugin if it uses the webroot
 authenticator with our ACME webroot.

 Return list Lineage names

=cut

sub _getOwnLineages
{
    my ( $self ) = @_;

    my $dir = $self->_certbotConfigDir() . '/renewal';
    return () unless -d $dir;

    my $webroot = $self->_webroot();
    my @names;
    for my $file ( grep { /\.conf\z/ } iMSCP::Dir->new( dirname => $dir )->getFiles() ) {
        ( my $name = $file ) =~ s/\.conf\z//;
        next unless _isValidDomainName( $name ) || $name =~ /^[a-z0-9.-]+-\d{4}$/;
        my $conf = $self->_readRenewalConf( $name ) or next;
        next unless ( $conf->{'authenticator'} // '' ) eq 'webroot'
            && grep ( $_ eq $webroot, split /\s*,\s*/, $conf->{'webroot_path'} // '' );
        push @names, $name;
    }

    @names;
}

=item _importCertificate( $type, $id, $name, $httpForward )

 Import the certificate of the given lineage into the i-MSCP ssl_certs table
 and schedule the rebuild of the entity

 Return string|undef Error message on failure, undef on success

=cut

sub _importCertificate
{
    my ( $self, $type, $id, $name, $httpForward ) = @_;

    my $liveDir = $self->_certbotConfigDir() . "/live/$name";
    my %pem;
    for my $part ( qw/ privkey cert chain / ) {
        my $content = -f "$liveDir/$part.pem"
            ? iMSCP::File->new( filename => "$liveDir/$part.pem" )->get() : undef;
        unless ( defined $content && $content =~ /-----BEGIN [A-Z ]+-----/ ) {
            return sprintf( "Couldn't read %s/%s.pem", $liveDir, $part );
        }
        $pem{$part} = $content;
    }

    # Let's Encrypt staging roots are not part of the system trust store. They
    # are appended to the CA bundle in staging mode, else i-MSCP would reject
    # the certificate chain.
    if ( $self->{'config'}->{'staging'} && !$self->_isTestMode() ) {
        my $roots = iMSCP::File->new( filename => "$self->{'pluginDir'}/backend/staging-roots.pem" )->get();
        $pem{'chain'} =~ s/\s*$/\n/;
        if ( defined $roots ) {
            $roots =~ s/^#.*\n//mg;
            $pem{'chain'} .= $roots;
        }
    }

    my $allowHsts = $httpForward ? 'on' : 'off';
    my $hstsMaxAge = $self->{'config'}->{'hsts_max_age'} // 31536000;
    $hstsMaxAge = 31536000 unless $hstsMaxAge =~ /^\d+$/;
    my $hstsIncludeSubdomains = $self->{'config'}->{'hsts_include_subdomains'} ? 'on' : 'off';

    local $@;
    eval {
        my $dbh = $self->{'dbh'};
        $dbh->begin_work();
        my ( $certId ) = $dbh->selectrow_array(
            'SELECT cert_id FROM ssl_certs WHERE domain_type = ? AND domain_id = ?', undef, $type, $id
        );
        if ( $certId ) {
            $dbh->do(
                "
                    UPDATE ssl_certs
                    SET private_key = ?, certificate = ?, ca_bundle = ?, allow_hsts = ?, hsts_max_age = ?,
                        hsts_include_subdomains = ?, status = 'tochange'
                    WHERE cert_id = ?
                ",
                undef, @pem{qw/ privkey cert chain /}, $allowHsts, $hstsMaxAge, $hstsIncludeSubdomains, $certId
            );
        } else {
            $dbh->do(
                "
                    INSERT INTO ssl_certs (
                        domain_id, domain_type, private_key, certificate, ca_bundle, allow_hsts, hsts_max_age,
                        hsts_include_subdomains, status
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, 'toadd'
                    )
                ",
                undef, $id, $type, @pem{qw/ privkey cert chain /}, $allowHsts, $hstsMaxAge, $hstsIncludeSubdomains
            );
        }
        $self->_setEntityStatus( $type, $id );
        $dbh->commit();
    };
    if ( $@ ) {
        my $err = $@;
        eval { $self->{'dbh'}->rollback(); };
        warning( $err );
        return "Couldn't import the certificate into i-MSCP: $err";
    }

    undef;
}

=item _deleteCertificate( $type, $id, \%entity )

 Remove the Let's Encrypt certificate from i-MSCP and delete the lineage

 The i-MSCP SSL certificate is only removed if it is one of the
 certificates of the lineage (it could have been replaced by the customer
 through the i-MSCP SSL certificate interface in the meantime).

 Return string|undef Error message on failure, undef on success

=cut

sub _deleteCertificate
{
    my ( $self, $type, $id, $entity ) = @_;

    my $name = lc $entity->{'name'};
    return sprintf( 'Invalid domain name: %s', $name ) unless _isValidDomainName( $name );

    local $@;
    eval {
        my $dbh = $self->{'dbh'};
        my $row = $dbh->selectrow_hashref(
            'SELECT cert_id, certificate, status FROM ssl_certs WHERE domain_type = ? AND domain_id = ?',
            undef, $type, $id
        );

        if ( $row && $row->{'status'} ne 'todelete' && $self->_isLineageCertificate( $name, $row->{'certificate'} ) ) {
            $dbh->begin_work();
            $dbh->do( "UPDATE ssl_certs SET status = 'todelete' WHERE cert_id = ?", undef, $row->{'cert_id'} );
            $self->_setEntityStatus( $type, $id );
            $dbh->commit();
        }
    };
    if ( $@ ) {
        my $err = $@;
        eval { $self->{'dbh'}->rollback(); };
        warning( $err );
        return "Couldn't remove the certificate from i-MSCP: $err";
    }

    if ( $self->{'config'}->{'revoke_on_delete'} ) {
        $self->_certbotRevoke( $name );
    }

    $self->_certbotDelete( $name );
    undef;
}

=item _isLineageCertificate( $name, $certificate )

 Whether the given certificate (PEM) is one of the certificates of the given lineage

 Return bool

=cut

sub _isLineageCertificate
{
    my ( $self, $name, $certificate ) = @_;

    return FALSE unless defined $certificate && length $certificate;

    my $dir = $self->_certbotConfigDir() . "/archive/$name";
    return FALSE unless -d $dir;

    ( my $needle = $certificate ) =~ s/\s+//g;
    for my $file ( grep { /^cert\d+\.pem\z/ } iMSCP::Dir->new( dirname => $dir )->getFiles() ) {
        my $content = iMSCP::File->new( filename => "$dir/$file" )->get();
        next unless defined $content;
        $content =~ s/\s+//g;
        return TRUE if $content eq $needle;
    }

    FALSE;
}

=item _certbotDelete( $name )

 Delete the given lineage (if it exists)

 Errors are logged as warnings only.

 Return int 0

=cut

sub _certbotDelete
{
    my ( $self, $name ) = @_;

    return 0 unless -f $self->_certbotConfigDir() . "/renewal/$name.conf";

    my $rs = execute(
        [ $self->_certbotBaseCmd(), 'delete', '--non-interactive', '--cert-name', $name ],
        \my $stdout, \my $stderr
    );
    debug( $stdout ) if length $stdout;
    warning( sprintf( "Couldn't delete the %s certificate lineage: %s", $name, $stderr || 'Unknown error' )) if $rs;
    0;
}

=item _certbotRevoke( $name )

 Revoke the current certificate of the given lineage (if it exists)

 Errors are logged as warnings only.

 Return int 0

=cut

sub _certbotRevoke
{
    my ( $self, $name ) = @_;

    return 0 unless -f $self->_certbotConfigDir() . "/renewal/$name.conf";

    my $renewalConf = $self->_readRenewalConf( $name ) || {};
    my $rs = execute(
        [
            $self->_certbotBaseCmd(), 'revoke', '--non-interactive', '--cert-name', $name,
            '--reason', 'cessationofoperation', '--no-delete-after-revoke',
            ( ( $renewalConf->{'server'} // '' ) =~ /staging/ ? '--test-cert' : () )
        ],
        \my $stdout, \my $stderr
    );
    debug( $stdout ) if length $stdout;
    warning( sprintf( "Couldn't revoke the %s certificate: %s", $name, $stderr || 'Unknown error' )) if $rs;
    0;
}

=item _collectGarbage( )

 Remove items which belong to entities that no longer exist

 Return int 0 on success, 1 on failure

=cut

sub _collectGarbage
{
    my ( $self ) = @_;

    local $@;
    my $rows = eval {
        $self->{'dbh'}->selectall_arrayref(
            "
                SELECT t1.letsencrypt_id, t1.cert_name
                FROM letsencrypt AS t1
                LEFT JOIN domain AS t2 ON(t1.alias_id IS NULL AND t1.subdomain_id IS NULL AND t2.domain_id = t1.domain_id)
                LEFT JOIN domain_aliasses AS t3 ON(t3.alias_id = t1.alias_id)
                LEFT JOIN subdomain AS t4 ON(t4.subdomain_id = t1.subdomain_id)
                WHERE t2.domain_id IS NULL AND t3.alias_id IS NULL AND t4.subdomain_id IS NULL
            ",
            { Slice => {} }
        );
    };
    if ( $@ ) {
        error( $@ );
        return 1;
    }

    for my $row ( @{ $rows } ) {
        $self->_certbotDelete( $row->{'cert_name'} ) if _isValidDomainName( $row->{'cert_name'} );
        eval { $self->{'dbh'}->do( 'DELETE FROM letsencrypt WHERE letsencrypt_id = ?', undef, $row->{'letsencrypt_id'} ); };
        if ( $@ ) {
            error( $@ );
            return 1;
        }
    }

    0;
}

=back

=head1 FUNCTIONS

=over 4

=item _isValidDomainName( $name )

 Whether the given name is a valid (ASCII/punycode) domain name

 Return bool

=cut

sub _isValidDomainName
{
    my ( $name ) = @_;

    defined $name && length $name <= 253
        && $name =~ /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\z/
        ? TRUE : FALSE;
}

=item _isValidEmail( $email )

 Basic email address validation (no whitespace, no shell/argument tricks)

 Return bool

=cut

sub _isValidEmail
{
    my ( $email ) = @_;

    defined $email && length $email <= 254 && $email =~ /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z0-9\-]{2,}\z/
        ? TRUE : FALSE;
}

=item _resolves( $name )

 Whether the given name resolves to an IPv4 or IPv6 address

 Return bool

=cut

sub _resolves
{
    my ( $name ) = @_;

    my ( $err, @res ) = getaddrinfo( $name, undef, { family => AF_UNSPEC, socktype => SOCK_STREAM } );
    !$err && @res ? TRUE : FALSE;
}

=item _certbotErrorMessage( $stderr, $stdout )

 Extract a concise error message from certbot output

 Return string

=cut

sub _certbotErrorMessage
{
    my ( $stderr, $stdout ) = @_;

    my $output = join "\n", grep { defined && length } $stderr, $stdout;
    my @lines = grep {
        length && !/^(?:Saving debug log|Ask for help|See the logfile|Some challenges have failed|Certbot failed to authenticate)/
    } map { s/^\s+|\s+$//gr } split /\n/, $output;

    # Prefer lines containing the ACME problem details
    my @details = grep {
        /^(?:Domain|Type|Detail|Hint|Error|Another instance|No certificate|[A-Za-z_.]+(?:Error|Exception):)/i
    } @lines;
    my $msg = join ' ', ( @details ? @details : ( @lines > 3 ? @lines[ -3 .. -1 ] : @lines ) );
    $msg =~ s/\s+/ /g;
    $msg;
}

=item _truncate( $string, $length )

 Truncate the given string

 Return string

=cut

sub _truncate
{
    my ( $string, $length ) = @_;

    $string //= '';
    length $string > $length ? substr( $string, 0, $length - 3 ) . '...' : $string;
}

=back

=head1 AUTHORS

 Cambell Prince <cambell.prince@gmail.com>

=cut

1;
__END__
