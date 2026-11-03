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
 * Generate list of items for the given entity type
 *
 * Only entities which belong to the logged-in customer are listed.
 *
 * @param TemplateEngine $tpl
 * @param string $type Entity type (domain|alias|subdomain)
 * @param string $block Template block name prefix (domain|als|sub)
 * @return int Number of listed items
 */
function letsencrypt_generateItems($tpl, $type, $block)
{
    switch ($type) {
        case 'domain':
            $query = '
                SELECT t1.domain_id AS id, t1.domain_name AS name, t1.domain_status AS entity_status,
                    t2.letsencrypt_id, t2.http_forward, t2.status, t2.state
                FROM domain AS t1
                LEFT JOIN letsencrypt AS t2 ON(
                    t2.domain_id = t1.domain_id AND t2.alias_id IS NULL AND t2.subdomain_id IS NULL
                )
                WHERE t1.domain_admin_id = ?
                ORDER BY t1.domain_name ASC, t2.letsencrypt_id DESC
            ';
            break;
        case 'alias':
            $query = "
                SELECT t1.alias_id AS id, t1.alias_name AS name, t1.alias_status AS entity_status,
                    t3.letsencrypt_id, t3.http_forward, t3.status, t3.state
                FROM domain_aliasses AS t1
                JOIN domain AS t2 USING(domain_id)
                LEFT JOIN letsencrypt AS t3 ON(t3.alias_id = t1.alias_id)
                WHERE t2.domain_admin_id = ?
                AND t1.alias_status <> 'ordered'
                ORDER BY t1.alias_name ASC, t3.letsencrypt_id DESC
            ";
            break;
        default:
            $query = "
                SELECT t1.subdomain_id AS id, CONCAT(t1.subdomain_name, '.', t2.domain_name) AS name,
                    t1.subdomain_status AS entity_status, t3.letsencrypt_id, t3.http_forward, t3.status, t3.state
                FROM subdomain AS t1
                JOIN domain AS t2 USING(domain_id)
                LEFT JOIN letsencrypt AS t3 ON(t3.subdomain_id = t1.subdomain_id)
                WHERE t2.domain_admin_id = ?
                ORDER BY name ASC, t3.letsencrypt_id DESC
            ";
    }

    $stmt = exec_query($query, array(intval($_SESSION['user_id'])));
    $seen = array();

    while ($row = $stmt->fetchRow(PDO::FETCH_ASSOC)) {
        // Only one item per entity (most recent one)
        if (isset($seen[$row['id']])) {
            continue;
        }

        $seen[$row['id']] = true;
        $enabled = $row['letsencrypt_id'] !== NULL && $row['status'] !== 'disabled';
        $status = $enabled ? $row['status'] : NULL;

        $tpl->assign(array(
            'DOMAIN_NAME'  => tohtml(decode_idna($row['name'])),
            'NOTE'         => tohtml((string)$row['state']),
            'EDIT'         => tohtml(tr('Edit')),
            'EDIT_LINK'    => tohtml('letsencrypt_edit.php?type=' . $type . '&id=' . intval($row['id']), 'htmlAttr'),
            'STATUS'       => tohtml(SGW_LetsEncrypt::translateStatus($status)),
            'STATUS_ICON'  => tohtml(SGW_LetsEncrypt::statusIcon($status), 'htmlAttr'),
            'HTTP_FORWARD' => tohtml($enabled && $row['http_forward'] ? tr('Yes') : tr('No'))
        ));
        $tpl->parse(strtoupper($block) . '_ITEM', '.' . $block . '_item');
    }

    return count($seen);
}

/***********************************************************************************************************************
 * Main
 */

check_login('user');
EventManager::getInstance()->dispatch(Events::onClientScriptStart);

if (!SGW_LetsEncrypt::customerHasLetsEncrypt(intval($_SESSION['user_id']))) {
    showBadRequestErrorPage();
}

$tpl = new TemplateEngine();
$tpl->define_dynamic(array(
    'layout'               => 'shared/layouts/ui.tpl',
    'page'                 => '../../plugins/SGW_LetsEncrypt/themes/default/view/client/letsencrypt.tpl',
    'page_message'         => 'layout',
    'domain_list'          => 'page',
    'domain_item'          => 'domain_list',
    'domain_aliases_block' => 'page',
    'als_message'          => 'domain_aliases_block',
    'als_list'             => 'domain_aliases_block',
    'als_item'             => 'als_list',
    'subdomains_block'     => 'page',
    'sub_message'          => 'subdomains_block',
    'sub_list'             => 'subdomains_block',
    'sub_item'             => 'sub_list'
));
$tpl->assign(array(
    'TR_PAGE_TITLE'     => tohtml(tr('Client / Domains / LetsEncrypt')),
    'TR_ACTION'         => tohtml(tr('Actions')),
    'TR_DOMAINS'        => tohtml(tr('Domains')),
    'TR_DOMAIN_ALIASES' => tohtml(tr('Domain aliases')),
    'TR_SUBDOMAINS'     => tohtml(tr('Subdomains')),
    'TR_DOMAIN_NAME'    => tohtml(tr('Domain')),
    'TR_HTTP_FORWARD'   => tohtml(tr('Redirect HTTP to HTTPS')),
    'TR_NOTE'           => tohtml(tr('Notes')),
    'TR_STATUS'         => tohtml(tr('Status'))
));

generateNavigation($tpl);

if (!letsencrypt_generateItems($tpl, 'domain', 'domain')) {
    $tpl->assign('DOMAIN_LIST', '');
}

if (letsencrypt_generateItems($tpl, 'alias', 'als')) {
    $tpl->assign('ALS_MESSAGE', '');
} else {
    $tpl->assign(array(
        'ALS_MSG'  => tohtml(tr('You do not have domain aliases.')),
        'ALS_LIST' => ''
    ));
}

if (letsencrypt_generateItems($tpl, 'subdomain', 'sub')) {
    $tpl->assign('SUB_MESSAGE', '');
} else {
    $tpl->assign(array(
        'SUB_MSG'  => tohtml(tr('You do not have subdomains.')),
        'SUB_LIST' => ''
    ));
}

generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventManager::getInstance()->dispatch(Events::onClientScriptEnd, array('templateEngine' => $tpl));
$tpl->prnt();
