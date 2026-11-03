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
 * Generate page (read-only overview of the LetsEncrypt certificates of the reseller's customers)
 *
 * @param TemplateEngine $tpl
 * @return void
 */
function letsencrypt_reseller_generatePage($tpl)
{
    $stmt = exec_query(
        "
            SELECT t1.cert_name, t1.http_forward, t1.status, t1.state, t2.admin_name
            FROM letsencrypt AS t1
            JOIN admin AS t2 ON(t2.admin_id = t1.admin_id)
            WHERE t2.created_by = ?
            AND t2.admin_type = 'user'
            AND t1.status <> 'disabled'
            ORDER BY t2.admin_name ASC, t1.cert_name ASC
        ",
        array(intval($_SESSION['user_id']))
    );

    if (!$stmt->rowCount()) {
        $tpl->assign('CUSTOMER_LIST', '');
        set_page_message(tr('No customer with LetsEncrypt support has been found.'), 'static_info');
        return;
    }

    while ($row = $stmt->fetchRow(PDO::FETCH_ASSOC)) {
        $tpl->assign(array(
            'CUSTOMER_NAME' => tohtml(decode_idna($row['admin_name'])),
            'DOMAIN_NAME'   => tohtml(decode_idna($row['cert_name'])),
            'STATUS'        => tohtml(SGW_LetsEncrypt::translateStatus($row['status'])),
            'STATUS_ICON'   => tohtml(SGW_LetsEncrypt::statusIcon($row['status']), 'htmlAttr'),
            'HTTP_FORWARD'  => tohtml($row['http_forward'] ? tr('Yes') : tr('No')),
            'NOTE'          => tohtml((string)$row['state'])
        ));
        $tpl->parse('CUSTOMER_ITEM', '.customer_item');
    }
}

/***********************************************************************************************************************
 * Main
 */

check_login('reseller');
EventManager::getInstance()->dispatch(Events::onResellerScriptStart);

if (!resellerHasCustomers()) {
    showBadRequestErrorPage();
}

$tpl = new TemplateEngine();
$tpl->define_dynamic(array(
    'layout'        => 'shared/layouts/ui.tpl',
    'page'          => '../../plugins/SGW_LetsEncrypt/themes/default/view/reseller/letsencrypt.tpl',
    'page_message'  => 'layout',
    'customer_list' => 'page',
    'customer_item' => 'customer_list'
));

$tpl->assign(array(
    'TR_PAGE_TITLE'   => tohtml(tr('Reseller / Customers / LetsEncrypt')),
    'TR_CUSTOMER'     => tohtml(tr('Customer')),
    'TR_DOMAIN_NAME'  => tohtml(tr('Domain Name')),
    'TR_STATUS'       => tohtml(tr('Status')),
    'TR_HTTP_FORWARD' => tohtml(tr('Redirect HTTP to HTTPS')),
    'TR_NOTE'         => tohtml(tr('Notes'))
));

generateNavigation($tpl);
letsencrypt_reseller_generatePage($tpl);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventManager::getInstance()->dispatch(Events::onResellerScriptEnd, array('templateEngine' => $tpl));
$tpl->prnt();
