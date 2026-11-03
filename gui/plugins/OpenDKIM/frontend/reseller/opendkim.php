<?php
/**
 * i-MSCP OpenDKIM plugin
 * Copyright (C) 2013-2017 Laurent Declercq <l.declercq@nuxwin.com>
 * Copyright (C) 2013-2016 Rene Schuster <mail@reneschuster.de>
 * Copyright (C) 2013-2016 Sascha Bay <info@space2place.de>
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

use iMSCP_Database as Database;
use iMSCP_Events as Events;
use iMSCP_Events_Aggregator as EventManager;
use iMSCP_Plugin_OpenDKIM as OpenDKIM;
use iMSCP_pTemplate as TemplateEngine;
use iMSCP_Registry as Registry;

/***********************************************************************************************************************
 * Functions
 */

/**
 * Is the plugin working at reseller level?
 *
 * @return bool
 */
function opendkim_isResellerWorkingLevel()
{
    return Registry::get('pluginManager')
            ->pluginGet('OpenDKIM')
            ->getConfigParam('plugin_working_level', 'reseller') == 'reseller';
}

/**
 * Get OpenDKIM status for the given customer
 *
 * - If all items statuses are 'ok', we return 'ok' status
 * - If there is one status denoting an error, we return it (the first found),
 *   else, we return the task status (again the first found)
 *
 * @param int $adminId
 * @return string
 */
function opendkim_getStatus($adminId)
{
    $stmt = exec_query(
        "SELECT opendkim_status FROM opendkim WHERE admin_id = ? AND opendkim_status <> 'ok' LIMIT 1", [$adminId]
    );

    if (!$stmt->rowCount()) {
        return 'ok';
    }

    $status = $stmt->fetchRow(PDO::FETCH_COLUMN);
    $stmt = exec_query(
        "
            SELECT opendkim_status
            FROM opendkim
            WHERE admin_id = ?
            AND opendkim_status NOT IN ('ok', 'toadd', 'todelete', 'tochange')
            LIMIT 1
        ",
        [$adminId]
    );

    return $stmt->fetchRow(PDO::FETCH_COLUMN) ?: $status;
}

/**
 * Send JSON response
 *
 * @param int $statusCode HTTP status code
 * @param array $data JSON data
 * @return void
 */
function opendkim_sendJsonResponse($statusCode = 200, array $data = [])
{
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
    header('Content-type: application/json');
    http_response_code(in_array($statusCode, [200, 202, 400, 403, 404, 405, 409, 500, 501]) ? $statusCode : 200);
    exit(json_encode($data));
}

/**
 * Get the customer (owned by the logged-in reseller) from the posted customer name
 *
 * @param string $condition Additional SQL condition
 * @return array|false Customer row (admin_id, admin_name) or FALSE if not found
 */
function opendkim_getPostedCustomer($condition = '')
{
    if (!isset($_POST['admin_name']) || !is_string($_POST['admin_name']) || $_POST['admin_name'] === '') {
        return false;
    }

    $stmt = exec_query(
        "
            SELECT admin_id, admin_name
            FROM admin
            WHERE admin_name = ?
            AND admin_type = 'user'
            AND created_by = ?
            AND admin_status = 'ok'
            $condition
        ",
        [encode_idna(clean_input($_POST['admin_name'])), $_SESSION['user_id']]
    );

    return $stmt->fetchRow(PDO::FETCH_ASSOC);
}

/**
 * Schedule renewal of all DKIM key that belong to the given customer
 *
 * @return void
 */
function opendkim_renewKeys()
{
    $customer = opendkim_getPostedCustomer('AND admin_id IN (SELECT admin_id FROM opendkim)');
    if (!$customer) {
        opendkim_sendJsonResponse(400, ['message' => tr('Bad request.')]);
    }

    $adminName = decode_idna($customer['admin_name']);

    try {
        exec_query(
            "UPDATE opendkim SET opendkim_status = 'tochange' WHERE admin_id = ? AND is_subdomain = 0 AND opendkim_status = 'ok'",
            [$customer['admin_id']]
        );
        send_request();
        write_log(
            sprintf('OpenDKIM keys for the %s customer were scheduled for renewal by %s.', $adminName, $_SESSION['user_logged']),
            E_USER_NOTICE
        );
        opendkim_sendJsonResponse(200, ['message' => tr('DKIM keys for the %s customer were scheduled for renewal.', $adminName)]);
    } catch (Exception $e) {
        write_log(
            sprintf("OpenDKIM: Couldn't schedule renewal of DKIM keys for the %s customer: %s", $adminName, $e->getMessage()),
            E_USER_ERROR
        );
        opendkim_sendJsonResponse(500, ['message' => tr('An unexpected error occurred. Please contact your administrator.')]);
    }
}

/**
 * Activate OpenDKIM for the given customer
 *
 * @return void
 */
function opendkim_activate()
{
    $customer = opendkim_getPostedCustomer('AND admin_id NOT IN (SELECT admin_id FROM opendkim)');
    if (!$customer) {
        opendkim_sendJsonResponse(400, ['message' => tr('Invalid customer.')]);
    }

    $adminName = decode_idna($customer['admin_name']);
    $db = Database::getInstance();

    try {
        $stmt = exec_query(
            "SELECT domain_id, domain_name FROM domain WHERE domain_admin_id = ? AND domain_status <> 'todelete'",
            [$customer['admin_id']]
        );

        if (!$stmt->rowCount()) {
            opendkim_sendJsonResponse(400, ['message' => tr('Invalid customer.')]);
        }

        $row = $stmt->fetchRow(PDO::FETCH_ASSOC);

        $db->beginTransaction();

        // Add entry for main domain name
        exec_query(
            "INSERT IGNORE INTO opendkim (admin_id, domain_id, domain_name, opendkim_status) VALUES (?, ?, ?, 'toadd')",
            [$customer['admin_id'], $row['domain_id'], $row['domain_name']]
        );

        // Add entries for domain aliases
        exec_query(
            "
                INSERT IGNORE INTO opendkim (admin_id, domain_id, alias_id, domain_name, opendkim_status)
                SELECT ?, domain_id, alias_id, alias_name, 'toadd'
                FROM domain_aliasses
                WHERE domain_id = ?
                AND alias_status NOT IN('todelete', 'ordered')
            ",
            [$customer['admin_id'], $row['domain_id']]
        );

        $db->commit();
        send_request();
        write_log(
            sprintf('OpenDKIM has been activated for the %s customer by %s.', $adminName, $_SESSION['user_logged']),
            E_USER_NOTICE
        );
        opendkim_sendJsonResponse(200, ['message' => tr('OpenDKIM will be activated for the %s customer.', $adminName)]);
    } catch (Exception $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }

        write_log(sprintf("OpenDKIM: Couldn't activate OpenDKIM for the %s customer: %s", $adminName, $e->getMessage()), E_USER_ERROR);
        opendkim_sendJsonResponse(500, ['message' => tr('An unexpected error occurred. Please contact your administrator.')]);
    }
}

/**
 * Deactivate OpenDKIM for the given customer
 *
 * @return void
 */
function opendkim_deactivate()
{
    $customer = opendkim_getPostedCustomer(
        "
            AND admin_id IN (SELECT admin_id FROM opendkim)
            AND admin_id NOT IN(SELECT admin_id FROM opendkim WHERE opendkim_status <> 'ok')
        "
    );
    if (!$customer) {
        opendkim_sendJsonResponse(400, ['message' => tr('Bad request.')]);
    }

    $adminName = decode_idna($customer['admin_name']);

    try {
        exec_query("UPDATE opendkim SET opendkim_status = 'todelete' WHERE admin_id = ?", [$customer['admin_id']]);
        send_request();
        write_log(
            sprintf('OpenDKIM has been deactivated for the %s customer by %s.', $adminName, $_SESSION['user_logged']),
            E_USER_NOTICE
        );
        opendkim_sendJsonResponse(200, ['message' => tr('OpenDKIM will be deactivated for the %s customer.', $adminName)]);
    } catch (Exception $e) {
        write_log(sprintf("OpenDKIM: Couldn't deactivate OpenDKIM for the %s customer: %s", $adminName, $e->getMessage()), E_USER_ERROR);
        opendkim_sendJsonResponse(500, ['message' => tr('An unexpected error occurred. Please contact your administrator.')]);
    }
}

/**
 * Escape LIKE wildcards
 *
 * @param string $string
 * @return string
 */
function opendkim_escapeLike($string)
{
    return addcslashes($string, '\\%_');
}

/**
 * Search customer for which OpenDKIM is not activated yet
 *
 * @return void
 */
function opendkim_searchCustomer()
{
    if (!isset($_GET['term']) || !is_string($_GET['term'])) {
        opendkim_sendJsonResponse(400, ['message' => tr('Bad request.')]);
    }

    try {
        $stmt = exec_query(
            "
                SELECT admin_name
                FROM admin
                WHERE admin_name LIKE ?
                AND admin_type = 'user'
                AND created_by = ?
                AND admin_status = 'ok'
                AND admin_id NOT IN(SELECT admin_id FROM opendkim)
                ORDER BY admin_name
                LIMIT 50
            ",
            [opendkim_escapeLike(encode_idna(clean_input($_GET['term']))) . '%', $_SESSION['user_id']]
        );
        opendkim_sendJsonResponse(200, $stmt->rowCount() ? array_map('decode_idna', $stmt->fetchAll(PDO::FETCH_COLUMN)) : []);
    } catch (Exception $e) {
        write_log(sprintf("OpenDKIM: Couldn't search customer: %s", $e->getMessage()), E_USER_ERROR);
        opendkim_sendJsonResponse(500, ['message' => tr('An unexpected error occurred. Please contact your administrator.')]);
    }
}

/**
 * Get list of customer for which OpenDKIM is activated (DataTables server-side processing)
 *
 * @return void
 */
function opendkim_getCustomerList()
{
    try {
        // Filterable / order-able columns (whitelist)
        $cols = ['admin_id', 'admin_name'];
        $nbCols = count($cols);
        $params = [$_SESSION['user_id']];

        /* Paging */
        $limit = '';
        if (isset($_GET['iDisplayStart']) && isset($_GET['iDisplayLength']) && $_GET['iDisplayLength'] !== '-1') {
            $limit = 'LIMIT ' . max(0, intval($_GET['iDisplayStart'])) . ', ' . max(1, min(1000, intval($_GET['iDisplayLength'])));
        }

        /* Ordering */
        $orderParts = [];
        if (isset($_GET['iSortingCols'])) {
            for ($i = 0, $nbSortingCols = min(intval($_GET['iSortingCols']), $nbCols); $i < $nbSortingCols; $i++) {
                if (!isset($_GET["iSortCol_$i"])) {
                    continue;
                }

                $colIdx = intval($_GET["iSortCol_$i"]);
                if (!isset($cols[$colIdx]) || !isset($_GET["bSortable_$colIdx"]) || $_GET["bSortable_$colIdx"] !== 'true') {
                    continue;
                }

                $sortDir = (isset($_GET["sSortDir_$i"]) && $_GET["sSortDir_$i"] === 'desc') ? 'DESC' : 'ASC';
                $orderParts[] = $cols[$colIdx] . ' ' . $sortDir;
            }
        }
        $order = $orderParts ? 'ORDER BY ' . implode(', ', $orderParts) : '';

        /* Filtering */
        $where = "WHERE admin_type = 'user' AND created_by = ?";
        if (isset($_GET['sSearch']) && is_string($_GET['sSearch']) && $_GET['sSearch'] !== '') {
            $where .= ' AND (admin_name LIKE ?)';
            $params[] = '%' . opendkim_escapeLike(encode_idna($_GET['sSearch'])) . '%';
        }

        /* Get data to display */
        $rResult = exec_query(
            "
                SELECT SQL_CALC_FOUND_ROWS DISTINCT admin_id, admin_name
                FROM opendkim AS t1
                INNER JOIN admin USING(admin_id)
                $where
                $order
                $limit
            ",
            $params
        );

        /* Data set length after filtering */
        $filteredTotal = execute_query('SELECT FOUND_ROWS()')->fetchRow(PDO::FETCH_COLUMN);

        /* Total data set length */
        $total = exec_query(
            "
                SELECT COUNT(DISTINCT admin_id)
                FROM opendkim
                INNER JOIN admin USING(admin_id)
                WHERE admin_type = 'user'
                AND created_by = ?
            ",
            [$_SESSION['user_id']]
        )->fetchRow(PDO::FETCH_COLUMN);

        /* Output */
        $output = [
            'sEcho'                => isset($_GET['sEcho']) ? intval($_GET['sEcho']) : 0,
            'iTotalRecords'        => (int)$total,
            'iTotalDisplayRecords' => (int)$filteredTotal,
            'aaData'               => []
        ];

        $trDeactivate = tohtml(tr('Deactivate'));
        $trRenewKeys = tohtml(tr('Renew keys'));
        $isResellerWorkingLevel = opendkim_isResellerWorkingLevel();

        while ($data = $rResult->fetchRow(PDO::FETCH_ASSOC)) {
            $adminName = decode_idna($data['admin_name']);
            $adminNameAttr = tohtml($adminName, 'htmlAttr');
            $row = ['admin_name' => tohtml($adminName)];

            if (($status = opendkim_getStatus($data['admin_id'])) == 'ok') {
                $row['status'] = tohtml(translate_dmn_status($status));
                $row['actions'] = <<<EOF
<span title="$trRenewKeys" data-action="renew_keys" data-admin-name="$adminNameAttr" class="icon i_reload clickable">$trRenewKeys</span>
EOF;
                if ($isResellerWorkingLevel) {
                    $row['actions'] .= <<<EOF

<span title="$trDeactivate" data-action="deactivate" data-admin-name="$adminNameAttr" class="icon i_delete clickable">$trDeactivate</span>
EOF;
                }
            } else {
                if (in_array($status, ['toadd', 'todelete', 'tochange'])) {
                    $row['status'] = tohtml(tr('Task(s) in progress...'));
                } else {
                    $row['status'] = tohtml(tr('An unexpected error occurred. Please contact your administrator.'));
                }

                $row['actions'] = tohtml(tr('N/A'));
            }

            $output['aaData'][] = $row;
        }

        opendkim_sendJsonResponse(200, $output);
    } catch (Exception $e) {
        write_log(sprintf('OpenDKIM: Could not get customer list: %s', $e->getMessage()), E_USER_ERROR);
        opendkim_sendJsonResponse(500, ['message' => tr('An unexpected error occurred. Please contact your administrator.')]);
    }
}

/***********************************************************************************************************************
 * Main
 */

check_login('reseller');
EventManager::getInstance()->dispatch(Events::onResellerScriptStart);
resellerHasCustomers() or showBadRequestErrorPage();

if (isset($_REQUEST['action'])) {
    if (!is_xhr()) {
        showBadRequestErrorPage();
    }

    $action = is_string($_REQUEST['action']) ? $_REQUEST['action'] : '';

    // State-changing actions: POST only, with valid CSRF token
    if (in_array($action, ['activate', 'deactivate', 'renew_keys'], true)) {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            opendkim_sendJsonResponse(405, ['message' => tr('Bad request.')]);
        }

        if (!OpenDKIM::checkCsrfToken()) {
            opendkim_sendJsonResponse(400, ['message' => tr('Invalid or missing security token. Please reload the page.')]);
        }

        if ($action != 'renew_keys' && !opendkim_isResellerWorkingLevel()) {
            opendkim_sendJsonResponse(400, ['message' => tr('Bad request.')]);
        }
    }

    switch ($action) {
        case 'get_customer_list':
            opendkim_getCustomerList();
            break;
        case 'search_customer':
            opendkim_searchCustomer();
            break;
        case 'activate':
            opendkim_activate();
            break;
        case 'deactivate':
            opendkim_deactivate();
            break;
        case 'renew_keys':
            opendkim_renewKeys();
            break;
        default:
            opendkim_sendJsonResponse(400, ['message' => tr('Bad request.')]);
    }
}

$tpl = new TemplateEngine();
$tpl->define_dynamic([
    'layout'       => 'shared/layouts/ui.tpl',
    'page'         => '../../plugins/OpenDKIM/themes/default/view/reseller/opendkim.phtml',
    'page_message' => 'layout',
]);
$tpl->assign('TR_PAGE_TITLE', tohtml(tr('Reseller / Customers / OpenDKIM')));
$tpl->isResellerWorkingLevel = opendkim_isResellerWorkingLevel();
$tpl->csrfToken = OpenDKIM::getCsrfToken();

generateNavigation($tpl);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventManager::getInstance()->dispatch(Events::onResellerScriptEnd, ['templateEngine' => $tpl]);
$tpl->prnt();
