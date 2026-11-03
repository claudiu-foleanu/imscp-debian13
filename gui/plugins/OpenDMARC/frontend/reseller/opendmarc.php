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
use iMSCP_Events_Aggregator as EventManager;
use iMSCP_Plugin_OpenDMARC as OpenDMARC;
use iMSCP_pTemplate as TemplateEngine;
use iMSCP_Registry as Registry;

/***********************************************************************************************************************
 * Functions
 */

/**
 * Generate page (read-only overview of the reseller's customers DMARC records)
 *
 * @param TemplateEngine $tpl
 * @param OpenDMARC $plugin
 * @return void
 */
function opendmarc_generatePage(TemplateEngine $tpl, OpenDMARC $plugin)
{
    $stmt = exec_query(
        "
            SELECT t1.domain_name, t1.policy, t1.subdomain_policy, t1.pct, t1.adkim, t1.aspf, t1.rua, t1.ruf,
                t1.opendmarc_status, t3.admin_name, t4.domain_text
            FROM opendmarc AS t1
            JOIN domain AS t2 ON(t2.domain_id = t1.domain_id)
            JOIN admin AS t3 ON(t3.admin_id = t2.domain_admin_id)
            LEFT JOIN domain_dns AS t4 ON(
                t4.domain_id = t1.domain_id
                AND t4.alias_id = IFNULL(t1.alias_id, 0)
                AND t4.owned_by = ?
                AND t4.domain_dns_status <> 'todelete'
            )
            WHERE t3.created_by = ?
            ORDER BY t3.admin_name, t1.domain_name
        ",
        [OpenDMARC::DNS_OWNER, (int)$_SESSION['user_id']]
    );

    if (!$stmt->rowCount()) {
        $tpl->assign('DMARC_ENTRIES', '');
        $tpl->assign('TR_NO_ENTRY', tohtml(tr('Your customers do not have any domain yet.')));
        $tpl->parse('DMARC_NO_ENTRY', 'dmarc_no_entry');
        return;
    }

    $tpl->assign('DMARC_NO_ENTRY', '');
    $defaults = $plugin->getDefaults();

    while ($row = $stmt->fetchRow(PDO::FETCH_ASSOC)) {
        $params = OpenDMARC::effectiveParams($row, $defaults);
        $record = $row['domain_text'] !== NULL ? trim(preg_replace('/"\s*"/', '', $row['domain_text']), '"') : '';

        $tpl->assign([
            'CUSTOMER_NAME' => tohtml(decode_idna($row['admin_name'])),
            'DOMAIN_NAME'   => tohtml(decode_idna($row['domain_name'])),
            'POLICY'        => tohtml($params['policy'] . ($row['policy'] === NULL ? ' (' . tr('default') . ')' : '')),
            'RECORD'        => tohtml($record !== '' ? $record : tr('N/A')),
            'STATUS'        => tohtml(OpenDMARC::translateStatus($row['opendmarc_status'])),
            'STATUS_ICON'   => tohtml(OpenDMARC::statusIcon($row['opendmarc_status']), 'htmlAttr')
        ]);
        $tpl->parse('DMARC_ENTRY', '.dmarc_entry');
    }
}

/***********************************************************************************************************************
 * Main
 */

check_login('reseller');
EventManager::getInstance()->dispatch(Events::onResellerScriptStart);

/** @var OpenDMARC $plugin */
$plugin = Registry::get('pluginManager')->pluginGet('OpenDMARC');

$tpl = new TemplateEngine();
$tpl->define_dynamic([
    'layout'         => 'shared/layouts/ui.tpl',
    'page'           => '../../plugins/OpenDMARC/themes/default/view/reseller/opendmarc.tpl',
    'page_message'   => 'layout',
    'dmarc_entries'  => 'page',
    'dmarc_entry'    => 'dmarc_entries',
    'dmarc_no_entry' => 'page'
]);

$tpl->assign([
    'TR_PAGE_TITLE' => tohtml(tr('Reseller / Customers / DMARC')),
    'TR_TITLE'      => tohtml(tr('DMARC policy records of your customers')),
    'TR_CUSTOMER'   => tohtml(tr('Customer')),
    'TR_DOMAIN'     => tohtml(tr('Domain')),
    'TR_POLICY'     => tohtml(tr('Policy')),
    'TR_RECORD'     => tohtml(tr('Published record')),
    'TR_STATUS'     => tohtml(tr('Status'))
]);

generateNavigation($tpl);
opendmarc_generatePage($tpl, $plugin);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventManager::getInstance()->dispatch(Events::onResellerScriptEnd, ['templateEngine' => $tpl]);
$tpl->prnt();
