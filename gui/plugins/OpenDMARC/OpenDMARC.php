<?php
/**
 * i-MSCP OpenDMARC plugin
 * Copyright (C) 2026 i-MSCP Debian 13 port
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

use iMSCP_Events as Events;
use iMSCP_Events_Event as Event;
use iMSCP_Events_Manager_Interface as EventsManagerInterface;
use iMSCP_Plugin_Action as PluginAction;
use iMSCP_Plugin_Exception as PluginException;
use iMSCP_Plugin_Manager as PluginManager;
use iMSCP_Registry as Registry;

/**
 * Class iMSCP_Plugin_OpenDMARC
 */
class iMSCP_Plugin_OpenDMARC extends PluginAction
{
    /**
     * @var string Session key holding the CSRF token
     */
    const CSRF_SESSION_KEY = 'opendmarc_csrf_token';

    /**
     * @var string Owner of the DMARC DNS resource records (domain_dns table)
     */
    const DNS_OWNER = 'OpenDMARC_Plugin';

    /**
     * @var array Allowed policies
     */
    public static $policies = ['none', 'quarantine', 'reject'];

    /**
     * @var array Item statuses for which a request is in progress
     */
    public static $pendingStatuses = ['toadd', 'tochange', 'todelete'];

    /**
     * @var string Report address regexp (must match the backend $EMAIL_RE)
     */
    const EMAIL_RE = '/^(?=.{3,254}\z)[a-z0-9_%+-]+(?:\.[a-z0-9_%+-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i';

    /**
     * Register event listeners
     *
     * @param EventsManagerInterface $em
     * @return void
     */
    public function register(EventsManagerInterface $em)
    {
        $em->registerListener(
            [
                Events::onResellerScriptStart,
                Events::onClientScriptStart,
                Events::onAfterAddCustomDNSrecord,
                Events::onAfterEditCustomDNSrecord,
                Events::onAfterDeleteCustomDNSrecord
            ],
            $this
        );
    }

    /**
     * Plugin installation
     *
     * @throws PluginException
     * @param PluginManager $pm
     * @return void
     */
    public function install(PluginManager $pm)
    {
        try {
            $this->migrateDb('up');
        } catch (Exception $e) {
            throw new PluginException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Plugin update
     *
     * @throws PluginException When update fail
     * @param PluginManager $pm
     * @param string $fromVersion Version from which plugin update is initiated
     * @param string $toVersion Version to which plugin is updated
     * @return void
     */
    public function update(PluginManager $pm, $fromVersion, $toVersion)
    {
        try {
            $this->migrateDb('up');
        } catch (Exception $e) {
            throw new PluginException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Plugin uninstallation
     *
     * @throws PluginException
     * @param PluginManager $pm
     * @return void
     */
    public function uninstall(PluginManager $pm)
    {
        try {
            $this->migrateDb('down');
        } catch (Exception $e) {
            throw new PluginException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * onResellerScriptStart event listener
     *
     * @return void
     */
    public function onResellerScriptStart()
    {
        $this->setupNavigation('reseller');
    }

    /**
     * onClientScriptStart event listener
     *
     * @return void
     */
    public function onClientScriptStart()
    {
        $this->setupNavigation('client');
    }

    /**
     * Re-evaluate the DMARC record when a customer adds a custom DNS record
     * (a customer-defined _dmarc record takes precedence)
     *
     * @param Event $e
     * @return void
     */
    public function onAfterAddCustomDNSrecord(Event $e)
    {
        self::scheduleReevaluation($e->getParam('domainId'), $e->getParam('aliasId'));
    }

    /**
     * Re-evaluate the DMARC record when a customer edits a custom DNS record
     *
     * @param Event $e
     * @return void
     */
    public function onAfterEditCustomDNSrecord(Event $e)
    {
        self::scheduleReevaluation($e->getParam('domainId'), $e->getParam('aliasId'));
    }

    /**
     * Re-evaluate the DMARC record when a customer deletes a custom DNS record
     * (the plugin record is re-published when a customer-defined _dmarc
     * record is removed)
     *
     * @param Event $e
     * @return void
     */
    public function onAfterDeleteCustomDNSrecord(Event $e)
    {
        $id = $e->getParam('id');
        if (!is_numeric($id)) {
            return;
        }

        $stmt = exec_query('SELECT domain_id, alias_id FROM domain_dns WHERE domain_dns_id = ?', [(int)$id]);
        if ($row = $stmt->fetchRow(PDO::FETCH_ASSOC)) {
            self::scheduleReevaluation($row['domain_id'], $row['alias_id']);
        }
    }

    /**
     * Get routes
     *
     * @return array
     */
    public function getRoutes()
    {
        $pluginDir = $this->getPluginManager()->pluginGetDirectory() . '/' . $this->getName();

        return [
            '/client/opendmarc'      => $pluginDir . '/frontend/client/opendmarc.php',
            '/client/opendmarc_edit' => $pluginDir . '/frontend/client/opendmarc_edit.php',
            '/reseller/opendmarc'    => $pluginDir . '/frontend/reseller/opendmarc.php'
        ];
    }

    /**
     * Get status of item with errors
     *
     * @return array
     */
    public function getItemWithErrorStatus()
    {
        $stmt = execute_query(
            "
                SELECT opendmarc_id AS item_id, opendmarc_status AS status, domain_name AS item_name,
                    'opendmarc' AS `table`, 'opendmarc_status' AS field
                FROM opendmarc
                WHERE opendmarc_status NOT IN('ok', 'toadd', 'tochange', 'todelete')
            "
        );

        if ($stmt->rowCount()) {
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        }

        return [];
    }

    /**
     * Set status of the given plugin item to 'tochange'
     *
     * @param string $table Table name
     * @param string $field Status field name
     * @param int $itemId item unique identifier
     * @return void
     */
    public function changeItemStatus($table, $field, $itemId)
    {
        if ($table == 'opendmarc' && $field == 'opendmarc_status') {
            exec_query("UPDATE opendmarc SET opendmarc_status = 'tochange' WHERE opendmarc_id = ?", [(int)$itemId]);
        }
    }

    /**
     * Return count of request in progress
     *
     * @return int
     */
    public function getCountRequests()
    {
        return (int)execute_query(
            "SELECT COUNT(opendmarc_id) FROM opendmarc WHERE opendmarc_status IN ('toadd', 'tochange', 'todelete')"
        )->fetchRow(PDO::FETCH_COLUMN);
    }

    /**
     * Schedule re-evaluation of the DMARC record of the given domain or domain alias
     *
     * @param int $domainId Main domain unique identifier
     * @param int $aliasId Domain alias unique identifier (0 for the main domain)
     * @return void
     */
    public static function scheduleReevaluation($domainId, $aliasId)
    {
        if (!is_numeric($domainId) || !is_numeric($aliasId)) {
            return;
        }

        exec_query(
            "
                UPDATE opendmarc SET opendmarc_status = 'tochange'
                WHERE domain_id = ? AND IFNULL(alias_id, 0) = ? AND opendmarc_status = 'ok'
            ",
            [(int)$domainId, (int)$aliasId]
        );
    }

    /**
     * Get the server-wide DMARC defaults (config.php)
     *
     * @return array
     */
    public function getDefaults()
    {
        return [
            'policy'           => (string)$this->getConfigParam('dmarc_policy', 'none'),
            'subdomain_policy' => (string)$this->getConfigParam('dmarc_subdomain_policy', ''),
            'pct'              => (string)$this->getConfigParam('dmarc_pct', 100),
            'adkim'            => (string)$this->getConfigParam('dmarc_adkim', 'r'),
            'aspf'             => (string)$this->getConfigParam('dmarc_aspf', 'r'),
            'rua'              => (string)$this->getConfigParam('dmarc_rua', ''),
            'ruf'              => (string)$this->getConfigParam('dmarc_ruf', '')
        ];
    }

    /**
     * Can customers edit their DMARC settings?
     *
     * @return bool
     */
    public function customerCanEdit()
    {
        return (bool)$this->getConfigParam('customer_can_edit', true);
    }

    /**
     * Merge the given per-domain settings (NULL = default) with the defaults
     *
     * @param array $row opendmarc table row
     * @param array $defaults Defaults
     * @return array
     */
    public static function effectiveParams(array $row, array $defaults)
    {
        $params = [];
        foreach ($defaults as $key => $value) {
            $params[$key] = (isset($row[$key]) && $row[$key] !== NULL) ? (string)$row[$key] : (string)$value;
        }

        return $params;
    }

    /**
     * Is the given value a valid DMARC report address?
     *
     * @param string $address
     * @return bool
     */
    public static function isValidReportAddress($address)
    {
        return is_string($address) && preg_match(self::EMAIL_RE, $address) === 1;
    }

    /**
     * Validate the given effective DMARC parameters
     *
     * @param array $p Parameters
     * @return bool
     */
    public static function isValidParams(array $p)
    {
        foreach (['policy', 'subdomain_policy', 'pct', 'adkim', 'aspf', 'rua', 'ruf'] as $key) {
            if (!isset($p[$key]) || !is_string($p[$key])) {
                return false;
            }
        }

        return in_array($p['policy'], self::$policies, true)
            && ($p['subdomain_policy'] === '' || in_array($p['subdomain_policy'], self::$policies, true))
            && preg_match('/^\d{1,3}\z/', $p['pct']) && (int)$p['pct'] >= 1 && (int)$p['pct'] <= 100
            && in_array($p['adkim'], ['r', 's'], true) && in_array($p['aspf'], ['r', 's'], true)
            && ($p['rua'] === '' || self::isValidReportAddress($p['rua']))
            && ($p['ruf'] === '' || self::isValidReportAddress($p['ruf']));
    }

    /**
     * Render the DMARC TXT record data (same output as the backend renderRecord())
     *
     * @param array $p Effective parameters
     * @return string|false Record data or FALSE if the parameters are invalid
     */
    public static function renderRecord(array $p)
    {
        if (!self::isValidParams($p)) {
            return false;
        }

        $tags = ['v=DMARC1', 'p=' . $p['policy']];
        if ($p['subdomain_policy'] !== '') {
            $tags[] = 'sp=' . $p['subdomain_policy'];
        }
        if ((int)$p['pct'] != 100) {
            $tags[] = 'pct=' . (int)$p['pct'];
        }
        if ($p['rua'] !== '') {
            $tags[] = 'rua=mailto:' . strtolower($p['rua']);
        }
        if ($p['ruf'] !== '') {
            $tags[] = 'ruf=mailto:' . strtolower($p['ruf']);
        }
        $tags[] = 'adkim=' . $p['adkim'];
        $tags[] = 'aspf=' . $p['aspf'];

        return implode('; ', $tags);
    }

    /**
     * Get status icon for the given item status
     *
     * @param string|null $status
     * @return string
     */
    public static function statusIcon($status)
    {
        if ($status === NULL) {
            return 'reload';
        }

        if ($status === 'ok') {
            return 'ok';
        }

        if ($status === 'disabled') {
            return 'disabled';
        }

        if (in_array($status, ['toadd', 'tochange', 'todelete', 'toenable', 'todisable'], true)) {
            return 'reload';
        }

        return 'error';
    }

    /**
     * Translate the given item status
     *
     * @param string|null $status
     * @return string
     */
    public static function translateStatus($status)
    {
        if ($status === NULL) {
            return tr('Addition in progress...');
        }

        return translate_dmn_status($status, true);
    }

    /**
     * Get (and create if needed) the CSRF token bound to the current session
     *
     * @return string
     */
    public static function getCsrfToken()
    {
        if (empty($_SESSION[self::CSRF_SESSION_KEY]) || !is_string($_SESSION[self::CSRF_SESSION_KEY])) {
            $_SESSION[self::CSRF_SESSION_KEY] = bin2hex(random_bytes(32));
        }

        return $_SESSION[self::CSRF_SESSION_KEY];
    }

    /**
     * Check the CSRF token sent with the current request
     *
     * @return bool TRUE if the token is valid, FALSE otherwise
     */
    public static function checkCsrfToken()
    {
        return !empty($_SESSION[self::CSRF_SESSION_KEY])
            && is_string($_SESSION[self::CSRF_SESSION_KEY])
            && isset($_POST['csrf_token'])
            && is_string($_POST['csrf_token'])
            && hash_equals($_SESSION[self::CSRF_SESSION_KEY], $_POST['csrf_token']);
    }

    /**
     * Inject OpenDMARC links into the navigation object
     *
     * @param string $level UI level
     * @return void;
     */
    protected function setupNavigation($level)
    {
        if (!Registry::isRegistered('navigation')) {
            return;
        }

        /** @var Zend_Navigation $navigation */
        $navigation = Registry::get('navigation');

        if ($level == 'client') {
            if (($page = $navigation->findOneBy('uri', '/client/domains_manage.php'))) {
                $page->addPage([
                    'label'       => tr('DMARC'),
                    'uri'         => '/client/opendmarc',
                    'title_class' => 'domains',
                    'pages'       => [
                        'opendmarc_edit' => [
                            'label'       => tr('Edit DMARC policy'),
                            'uri'         => '/client/opendmarc_edit',
                            // Must not be set invisible, else the page is
                            // never found as active page by the layout
                            // (hidden from menus through the menu depth, as
                            // for core pages)
                            'title_class' => 'domains'
                        ]
                    ]
                ]);
            }

            return;
        }

        if (!($page = $navigation->findOneBy('uri', '/reseller/users.php'))) {
            return;
        }

        $page->addPage([
            'label'              => tr('DMARC'),
            'uri'                => '/reseller/opendmarc',
            'title_class'        => 'users',
            'privilege_callback' => [
                'name' => 'resellerHasCustomers'
            ]
        ]);
    }
}
