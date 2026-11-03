<?php
/**
 * i-MSCP LetsEncrypt plugin
 * Copyright (C) 2017 Cambell Prince <cambell.prince@gmail.com>
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

/**
 * Class iMSCP_Plugin_SGW_LetsEncrypt
 */
class iMSCP_Plugin_SGW_LetsEncrypt extends iMSCP_Plugin_Action
{
    /**
     * Name of the session key holding the CSRF token
     */
    const CSRF_SESSION_KEY = 'sgw_letsencrypt_csrf_token';

    /**
     * Statuses for which an item is being processed by the backend
     *
     * @var array
     */
    public static $pendingStatuses = array('toadd', 'tochange', 'todelete');

    /**
     * Plugin initialization
     *
     * @return void
     */
    public function init()
    {
        l10n_addTranslations(__DIR__ . '/l10n', 'Array', $this->getName());
    }

    /**
     * Get plugin name
     *
     * The plugin name contains an underscore. The generic implementation
     * derives the name from the class name, using the part after the last
     * underscore, which would give 'LetsEncrypt'.
     *
     * @return string
     */
    public function getName()
    {
        return 'SGW_LetsEncrypt';
    }

    /**
     * Register event listeners
     *
     * @param iMSCP_Events_Manager_Interface $eventsManager
     * @return void
     */
    public function register(iMSCP_Events_Manager_Interface $eventsManager)
    {
        $eventsManager->registerListener(
            array(
                iMSCP_Events::onResellerScriptStart,
                iMSCP_Events::onClientScriptStart,
                iMSCP_Events::onAfterDeleteDomainAlias,
                iMSCP_Events::onAfterDeleteSubdomain,
                iMSCP_Events::onAfterDeleteCustomer
            ),
            $this
        );
    }

    /**
     * Plugin installation
     *
     * @throws iMSCP_Plugin_Exception
     * @param iMSCP_Plugin_Manager $pluginManager
     * @return void
     */
    public function install(iMSCP_Plugin_Manager $pluginManager)
    {
        try {
            $this->migrateDb('up');
        } catch (Exception $e) {
            throw new iMSCP_Plugin_Exception($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Plugin update
     *
     * @throws iMSCP_Plugin_Exception When update fail
     * @param iMSCP_Plugin_Manager $pluginManager
     * @param string $fromVersion Version from which plugin update is initiated
     * @param string $toVersion Version to which plugin is updated
     * @return void
     */
    public function update(iMSCP_Plugin_Manager $pluginManager, $fromVersion, $toVersion)
    {
        try {
            $this->migrateDb('up');
            $this->clearTranslations();
        } catch (Exception $e) {
            throw new iMSCP_Plugin_Exception($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Plugin uninstallation
     *
     * @throws iMSCP_Plugin_Exception
     * @param iMSCP_Plugin_Manager $pluginManager
     * @return void
     */
    public function uninstall(iMSCP_Plugin_Manager $pluginManager)
    {
        try {
            $this->migrateDb('down');
            $this->clearTranslations();
        } catch (Exception $e) {
            throw new iMSCP_Plugin_Exception($e->getMessage(), $e->getCode(), $e);
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
        if (isset($_SESSION['user_id']) && self::customerHasLetsEncrypt(intval($_SESSION['user_id']))) {
            $this->setupNavigation('client');
        }
    }

    /**
     * onAfterDeleteCustomer event listener
     *
     * The backend removes the lineages of items which belong to entities that
     * are being deleted (or which no longer exist).
     *
     * @param iMSCP_Events_Event $event
     * @return void
     */
    public function onAfterDeleteCustomer(iMSCP_Events_Event $event)
    {
        exec_query("UPDATE letsencrypt SET status = 'todelete' WHERE admin_id = ?", array(
            intval($event->getParam('customerId'))
        ));
    }

    /**
     * onAfterDeleteDomainAlias event listener
     *
     * @param iMSCP_Events_Event $event
     * @return void
     */
    public function onAfterDeleteDomainAlias(iMSCP_Events_Event $event)
    {
        exec_query("UPDATE letsencrypt SET status = 'todelete' WHERE alias_id = ?", array(
            intval($event->getParam('domainAliasId'))
        ));
    }

    /**
     * onAfterDeleteSubdomain event listener
     *
     * @param iMSCP_Events_Event $event
     * @return void
     */
    public function onAfterDeleteSubdomain(iMSCP_Events_Event $event)
    {
        // Subdomains of domain aliases are not supported by this plugin
        if ($event->getParam('subdomainType') !== 'sub') {
            return;
        }

        exec_query("UPDATE letsencrypt SET status = 'todelete' WHERE subdomain_id = ?", array(
            intval($event->getParam('subdomainId'))
        ));
    }

    /**
     * Get routes
     *
     * @return array
     */
    public function getRoutes()
    {
        $pluginDir = $this->getPluginManager()->pluginGetRootDir() . '/' . $this->getName();

        return array(
            '/reseller/letsencrypt.php'    => $pluginDir . '/frontend/reseller/letsencrypt.php',
            '/client/letsencrypt.php'      => $pluginDir . '/frontend/client/letsencrypt.php',
            '/client/letsencrypt_edit.php' => $pluginDir . '/frontend/client/letsencrypt_edit.php'
        );
    }

    /**
     * Get status of item with errors
     *
     * @return array
     */
    public function getItemWithErrorStatus()
    {
        $stmt = exec_query(
            "
                SELECT letsencrypt_id AS item_id, cert_name AS item_name, status,
                    'letsencrypt' AS `table`, 'status' AS field
                FROM letsencrypt WHERE status NOT IN(?, ?, ?, ?, ?)
            ",
            array('ok', 'disabled', 'toadd', 'tochange', 'todelete')
        );

        if ($stmt->rowCount()) {
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        }

        return array();
    }

    /**
     * Set status of the given plugin item to 'tochange'
     *
     * @param string $table Table name
     * @param string $field Status field name
     * @param int $itemId LetsEncrypt item unique identifier
     * @return void
     */
    public function changeItemStatus($table, $field, $itemId)
    {
        if ($table == 'letsencrypt' && $field == 'status') {
            exec_query('UPDATE letsencrypt SET `status` = ? WHERE letsencrypt_id = ?', array('tochange', intval($itemId)));
        }
    }

    /**
     * Return count of request in progress
     *
     * @return int
     */
    public function getCountRequests()
    {
        $stmt = exec_query(
            'SELECT COUNT(letsencrypt_id) AS cnt FROM letsencrypt WHERE `status` IN (?, ?, ?)',
            self::$pendingStatuses
        );

        $row = $stmt->fetchRow(PDO::FETCH_ASSOC);

        return intval($row['cnt']);
    }

    /**
     * Does the given customer has LetsEncrypt feature activated?
     *
     * Let's Encrypt is available to customers when the SSL feature is enabled
     * on the panel (same condition as for the i-MSCP SSL certificate
     * interface).
     *
     * @param int $customerId Customer unique identifier
     * @return bool
     */
    public static function customerHasLetsEncrypt($customerId)
    {
        if (!$customerId || !function_exists('customerHasFeature')) {
            return false;
        }

        return (bool)customerHasFeature('ssl');
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
     * Check the CSRF token sent with the current (POST) request
     *
     * Raise a bad request error on failure.
     *
     * @return void
     */
    public static function checkCsrfToken()
    {
        if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST'
            || !isset($_POST['csrf_token']) || !is_string($_POST['csrf_token'])
            || empty($_SESSION[self::CSRF_SESSION_KEY]) || !is_string($_SESSION[self::CSRF_SESSION_KEY])
            || !hash_equals($_SESSION[self::CSRF_SESSION_KEY], $_POST['csrf_token'])
        ) {
            showBadRequestErrorPage();
        }
    }

    /**
     * Get translated status of an item
     *
     * @param string|null $status Item status
     * @return string
     */
    public static function translateStatus($status)
    {
        if ($status === NULL || $status === '' || $status === 'disabled') {
            return tr('Disabled');
        }

        switch ($status) {
            case 'ok':
                return tr('Enabled');
            case 'toadd':
                return tr('Certificate request in progress...');
            case 'tochange':
                return tr('Modification in progress...');
            case 'todelete':
                return tr('Deletion in progress...');
            default:
                return tr('Error: %s', $status);
        }
    }

    /**
     * Get status icon of an item
     *
     * @param string|null $status Item status
     * @return string
     */
    public static function statusIcon($status)
    {
        if ($status === NULL || $status === '' || $status === 'disabled') {
            return 'disabled';
        }

        if ($status === 'ok') {
            return 'ok';
        }

        if (in_array($status, self::$pendingStatuses, true)) {
            return 'reload';
        }

        return 'error';
    }

    /**
     * Inject LetsEncrypt links into the navigation object
     *
     * @param string $level UI level
     */
    protected function setupNavigation($level)
    {
        if (iMSCP_Registry::isRegistered('navigation')) {
            /** @var Zend_Navigation $navigation */
            $navigation = iMSCP_Registry::get('navigation');

            if ($level == 'reseller') {
                if (($page = $navigation->findOneBy('uri', '/reseller/users.php'))) {
                    $page->addPage(array(
                        'label'              => tr('LetsEncrypt'),
                        'uri'                => '/reseller/letsencrypt.php',
                        'title_class'        => 'users',
                        'privilege_callback' => array(
                            'name' => 'resellerHasCustomers'
                        )
                    ));
                }
            } elseif ($level == 'client') {
                if (($page = $navigation->findOneBy('uri', '/client/domains_manage.php'))) {
                    $page->addPage(array(
                        'label'       => tr('LetsEncrypt'),
                        'uri'         => '/client/letsencrypt.php',
                        'title_class' => 'domains',
                        'pages'       => array(
                            'letsencrypt_edit' => array(
                                'label'       => tr('LetsEncrypt Edit'),
                                'uri'         => '/client/letsencrypt_edit.php',
                                // Must not be set invisible, else the page is
                                // never found as active page by the layout
                                // (hidden from menus through the menu depth,
                                // as for core pages)
                                'title_class' => 'domains'
                            )
                        )
                    ));
                }
            }
        }
    }

    /**
     * Clear translations if any
     *
     * @return void
     */
    protected function clearTranslations()
    {
        if (!iMSCP_Registry::isRegistered('translator')) {
            return;
        }

        /** @var Zend_Translate $translator */
        $translator = iMSCP_Registry::get('translator');

        if ($translator->hasCache()) {
            $translator->clearCache($this->getName());
        }
    }
}
