<?php
/**
 * i-MSCP SGW_LetsEncrypt plugin
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

namespace SGW_LetsEncrypt;

use iMSCP_Events as Events;
use iMSCP_Events_Aggregator as EventManager;
use iMSCP_Plugin_SGW_LetsEncrypt as SGW_LetsEncrypt;
use iMSCP_pTemplate as TemplateEngine;
use PDO;

/***********************************************************************************************************************
 * Functions
 */

/**
 * Get entity and LetsEncrypt item data
 *
 * Only entities which belong to the logged-in customer are returned.
 *
 * @param string $type Entity type (domain|alias|subdomain)
 * @param int $id Entity unique identifier
 * @return array|false Data or false if the entity doesn't exist or doesn't belong to the customer
 */
function letsencrypt_getEditData($type, $id)
{
    switch ($type) {
        case 'domain':
            $query = '
                SELECT t1.domain_id AS id, t1.domain_name AS name, t1.domain_status AS entity_status
                FROM domain AS t1
                WHERE t1.domain_id = ? AND t1.domain_admin_id = ?
            ';
            $itemCond = 'domain_id = ? AND alias_id IS NULL AND subdomain_id IS NULL';
            break;
        case 'alias':
            $query = "
                SELECT t1.alias_id AS id, t1.alias_name AS name, t1.alias_status AS entity_status
                FROM domain_aliasses AS t1
                JOIN domain AS t2 USING(domain_id)
                WHERE t1.alias_id = ? AND t2.domain_admin_id = ? AND t1.alias_status <> 'ordered'
            ";
            $itemCond = 'alias_id = ?';
            break;
        case 'subdomain':
            $query = "
                SELECT t1.subdomain_id AS id, CONCAT(t1.subdomain_name, '.', t2.domain_name) AS name,
                    t1.subdomain_status AS entity_status
                FROM subdomain AS t1
                JOIN domain AS t2 USING(domain_id)
                WHERE t1.subdomain_id = ? AND t2.domain_admin_id = ?
            ";
            $itemCond = 'subdomain_id = ?';
            break;
        default:
            return false;
    }

    $stmt = exec_query($query, array($id, intval($_SESSION['user_id'])));
    if (!$stmt->rowCount()) {
        return false;
    }

    $data = $stmt->fetchRow(PDO::FETCH_ASSOC);

    $stmt = exec_query(
        "SELECT letsencrypt_id, http_forward, status, state FROM letsencrypt WHERE $itemCond ORDER BY letsencrypt_id DESC",
        array($id)
    );
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $data['item'] = !empty($items) ? $items[0] : NULL;
    $data['duplicate_ids'] = array();
    for ($i = 1, $count = count($items); $i < $count; $i++) {
        $data['duplicate_ids'][] = intval($items[$i]['letsencrypt_id']);
    }

    // Placeholder rows created by plugin versions < 1.6.0
    $data['enabled'] = $data['item'] !== NULL && $data['item']['status'] !== 'disabled';

    return $data;
}

/**
 * Update LetsEncrypt settings of the given entity
 *
 * @param string $type Entity type (domain|alias|subdomain)
 * @param int $id Entity unique identifier
 * @param array $data Entity data
 * @return bool TRUE on success, FALSE on failure
 */
function letsencrypt_update($type, $id, array $data)
{
    SGW_LetsEncrypt::checkCsrfToken();

    if (!isset($_POST['enabled']) || !in_array($_POST['enabled'], array('yes', 'no'), true)
        || !isset($_POST['http_forward']) || !in_array($_POST['http_forward'], array('yes', 'no'), true)
    ) {
        showBadRequestErrorPage();
    }

    $item = $data['item'];
    if ($item !== NULL && in_array($item['status'], SGW_LetsEncrypt::$pendingStatuses, true)) {
        set_page_message(tr('A request is already in progress for this domain. Please retry later.'), 'error');
        return false;
    }

    $enable = $_POST['enabled'] === 'yes';
    $httpForward = $enable && $_POST['http_forward'] === 'yes' ? 1 : 0;

    if ($enable && $data['entity_status'] !== 'ok') {
        set_page_message(tr('The domain must be active to enable LetsEncrypt.'), 'error');
        return false;
    }

    $db = \iMSCP_Database::getInstance();

    try {
        $db->beginTransaction();

        // Remove duplicate items, if any (plugin versions < 1.6.0)
        foreach ($data['duplicate_ids'] as $duplicateId) {
            exec_query('DELETE FROM letsencrypt WHERE letsencrypt_id = ?', array($duplicateId));
        }

        if ($enable) {
            if ($data['enabled']) {
                exec_query(
                    "UPDATE letsencrypt SET http_forward = ?, status = 'tochange' WHERE letsencrypt_id = ?",
                    array($httpForward, $item['letsencrypt_id'])
                );
            } elseif ($item !== NULL) {
                exec_query(
                    "UPDATE letsencrypt SET http_forward = ?, cert_name = ?, status = 'toadd', state = '' WHERE letsencrypt_id = ?",
                    array($httpForward, $data['name'], $item['letsencrypt_id'])
                );
            } else {
                exec_query(
                    "
                        INSERT INTO letsencrypt (
                            admin_id, domain_id, alias_id, subdomain_id, cert_name, http_forward, status, state
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, 'toadd', ''
                        )
                    ",
                    array(
                        intval($_SESSION['user_id']),
                        $type == 'domain' ? $id : 0,
                        $type == 'alias' ? $id : NULL,
                        $type == 'subdomain' ? $id : NULL,
                        $data['name'],
                        $httpForward
                    )
                );
            }
        } elseif ($data['enabled']) {
            exec_query(
                "UPDATE letsencrypt SET status = 'todelete' WHERE letsencrypt_id = ?",
                array($item['letsencrypt_id'])
            );
        } elseif ($item !== NULL) {
            // Legacy placeholder: nothing to undo
            exec_query('DELETE FROM letsencrypt WHERE letsencrypt_id = ?', array($item['letsencrypt_id']));
        }

        $db->commit();
    } catch (\Exception $e) {
        $db->rollBack();
        throw $e;
    }

    send_request();
    write_log(
        sprintf(
            '%s updated LetsEncrypt settings of the %s domain (%s)',
            $_SESSION['user_logged'],
            decode_idna($data['name']),
            $enable ? 'enabled' : 'disabled'
        ),
        E_USER_NOTICE
    );

    return true;
}

/**
 * Generate page
 *
 * @param TemplateEngine $tpl
 * @param string $type Entity type
 * @param int $id Entity unique identifier
 * @param array $data Entity data
 * @return void
 */
function letsencrypt_edit_generatePage($tpl, $type, $id, array $data)
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['enabled'])) {
        $enabled = $_POST['enabled'] === 'yes';
        $httpForward = isset($_POST['http_forward']) && $_POST['http_forward'] === 'yes';
    } else {
        $enabled = $data['enabled'];
        $httpForward = $data['enabled'] && $data['item']['http_forward'];
    }

    $status = $data['enabled'] ? $data['item']['status'] : NULL;

    $tpl->assign(array(
        'FORM_ACTION'      => tohtml('letsencrypt_edit.php?type=' . $type . '&id=' . $id, 'htmlAttr'),
        'CSRF_TOKEN'       => tohtml(SGW_LetsEncrypt::getCsrfToken(), 'htmlAttr'),
        'DOMAIN_NAME'      => tohtml(decode_idna($data['name'])),
        'STATUS'           => tohtml(SGW_LetsEncrypt::translateStatus($status)),
        'NOTE'             => tohtml($data['enabled'] ? (string)$data['item']['state'] : ''),
        'ENABLED_YES'      => $enabled ? ' checked' : '',
        'ENABLED_NO'       => $enabled ? '' : ' checked',
        'HTTP_FORWARD_YES' => $httpForward ? ' checked' : '',
        'HTTP_FORWARD_NO'  => $httpForward ? '' : ' checked'
    ));
}

/***********************************************************************************************************************
 * Main
 */

check_login('user');
EventManager::getInstance()->dispatch(Events::onClientScriptStart);

if (!SGW_LetsEncrypt::customerHasLetsEncrypt(intval($_SESSION['user_id']))) {
    showBadRequestErrorPage();
}

if (!isset($_GET['type']) || !isset($_GET['id']) || !is_string($_GET['type']) || !is_string($_GET['id'])
    || !in_array($_GET['type'], array('domain', 'alias', 'subdomain'), true)
    || !ctype_digit($_GET['id'])
) {
    showBadRequestErrorPage();
}

$type = $_GET['type'];
$id = intval($_GET['id']);
$data = letsencrypt_getEditData($type, $id);

if ($data === false) {
    showNotFoundErrorPage();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (letsencrypt_update($type, $id, $data)) {
        set_page_message(tr('LetsEncrypt settings successfully scheduled for update.'), 'success');
        redirectTo('letsencrypt.php');
    }
}

$tpl = new TemplateEngine();
$tpl->define_dynamic(array(
    'layout'       => 'shared/layouts/ui.tpl',
    'page'         => '../../plugins/SGW_LetsEncrypt/themes/default/view/client/letsencrypt_edit.tpl',
    'page_message' => 'layout'
));
$tpl->assign(array(
    'TR_PAGE_TITLE'           => tohtml(tr('Client / Domains / LetsEncrypt / Edit')),
    'TR_YES'                  => tohtml(tr('Yes')),
    'TR_NO'                   => tohtml(tr('No')),
    'TR_UPDATE'               => tohtml(tr('Update'), 'htmlAttr'),
    'TR_CANCEL'               => tohtml(tr('Cancel')),
    'TR_DOMAIN'               => tohtml(tr('Domain')),
    'TR_DOMAIN_NAME'          => tohtml(tr('Domain name')),
    'TR_STATUS'               => tohtml(tr('Status')),
    'TR_NOTE'                 => tohtml(tr('Notes')),
    'TR_ENABLED'              => tohtml(tr('LetsEncrypt certificate')),
    'TR_ENABLED_TOOLTIP'      => tohtml(
        tr("Obtain a Let's Encrypt certificate for this domain (and its www. name when it resolves) and keep it renewed automatically. The domain must point to this server."),
        'htmlAttr'
    ),
    'TR_HTTP_FORWARD'         => tohtml(tr('Redirect HTTP to HTTPS')),
    'TR_HTTP_FORWARD_TOOLTIP' => tohtml(
        tr('Permanently redirect HTTP requests to HTTPS and enable HSTS.'), 'htmlAttr'
    )
));

generateNavigation($tpl);
letsencrypt_edit_generatePage($tpl, $type, $id, $data);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventManager::getInstance()->dispatch(Events::onClientScriptEnd, array('templateEngine' => $tpl));
$tpl->prnt();
