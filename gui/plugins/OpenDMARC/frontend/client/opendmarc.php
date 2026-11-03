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
 * Get the DMARC entries of the current customer (domains and domain aliases)
 *
 * @param int $customerId Customer unique identifier
 * @return array
 */
function opendmarc_getCustomerEntries($customerId)
{
    $stmt = exec_query(
        "
            SELECT t1.domain_id, 0 AS alias_id, t1.domain_name AS name, t1.domain_status AS entity_status,
                t2.opendmarc_id, t2.policy, t2.subdomain_policy, t2.pct, t2.adkim, t2.aspf, t2.rua, t2.ruf,
                t2.opendmarc_status
            FROM domain AS t1
            LEFT JOIN opendmarc AS t2 ON(t2.domain_id = t1.domain_id AND t2.alias_id IS NULL)
            WHERE t1.domain_admin_id = ?
            UNION ALL
            SELECT t1.domain_id, t1.alias_id, t1.alias_name AS name, t1.alias_status AS entity_status,
                t3.opendmarc_id, t3.policy, t3.subdomain_policy, t3.pct, t3.adkim, t3.aspf, t3.rua, t3.ruf,
                t3.opendmarc_status
            FROM domain_aliasses AS t1
            JOIN domain AS t2 ON(t2.domain_id = t1.domain_id)
            LEFT JOIN opendmarc AS t3 ON(t3.alias_id = t1.alias_id)
            WHERE t2.domain_admin_id = ?
            AND t1.alias_status <> 'ordered'
            ORDER BY name
        ",
        [$customerId, $customerId]
    );

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get the DMARC/DKIM DNS records of the current customer, indexed by
 * "<domain_id>:<alias_id>"
 *
 * @param int $customerId Customer unique identifier
 * @param array $entries Customer entries (zone names)
 * @return array
 */
function opendmarc_getCustomerDnsRecords($customerId, array $entries)
{
    $zones = [];
    foreach ($entries as $entry) {
        $zones[$entry['domain_id'] . ':' . $entry['alias_id']] = strtolower($entry['name']);
    }

    $stmt = exec_query(
        "
            SELECT t1.domain_id, t1.alias_id, t1.domain_dns, t1.domain_text, t1.owned_by, t1.domain_dns_status
            FROM domain_dns AS t1
            JOIN domain AS t2 ON(t2.domain_id = t1.domain_id)
            WHERE t2.domain_admin_id = ?
            AND t1.domain_dns_status <> 'todelete'
            AND (t1.owned_by IN(?, 'OpenDKIM_Plugin') OR t1.domain_dns LIKE '\\_dmarc%')
        ",
        [$customerId, OpenDMARC::DNS_OWNER]
    );

    $records = [];
    while ($row = $stmt->fetchRow(PDO::FETCH_ASSOC)) {
        $key = $row['domain_id'] . ':' . $row['alias_id'];
        if (!isset($zones[$key])) {
            continue;
        }

        if (!isset($records[$key])) {
            $records[$key] = ['dmarc' => NULL, 'dmarc_status' => NULL, 'dkim' => false, 'custom' => false];
        }

        if ($row['owned_by'] === OpenDMARC::DNS_OWNER) {
            $records[$key]['dmarc'] = $row['domain_text'];
            $records[$key]['dmarc_status'] = $row['domain_dns_status'];
            continue;
        }

        if ($row['owned_by'] === 'OpenDKIM_Plugin') {
            if (strpos($row['domain_dns'], 'mail._domainkey') === 0) {
                $records[$key]['dkim'] = true;
            }
            continue;
        }

        // Customer-defined _dmarc record (custom DNS feature)
        $name = strtolower(rtrim(preg_split('/\s+/', $row['domain_dns'])[0], '.'));
        if ($name === '_dmarc' || $name === '_dmarc.' . $zones[$key]) {
            $records[$key]['custom'] = true;
        }
    }

    return $records;
}

/**
 * Generate page
 *
 * @param TemplateEngine $tpl
 * @param OpenDMARC $plugin
 * @return void
 */
function opendmarc_generatePage(TemplateEngine $tpl, OpenDMARC $plugin)
{
    $customerId = (int)$_SESSION['user_id'];
    $entries = opendmarc_getCustomerEntries($customerId);

    if (empty($entries)) {
        $tpl->assign('DMARC_ENTRIES', '');
        $tpl->assign('TR_NO_ENTRY', tohtml(tr('You do not have any domain yet.')));
        $tpl->parse('DMARC_NO_ENTRY', 'dmarc_no_entry');
        return;
    }

    $tpl->assign('DMARC_NO_ENTRY', '');

    $records = opendmarc_getCustomerDnsRecords($customerId, $entries);
    $defaults = $plugin->getDefaults();
    $canEdit = $plugin->customerCanEdit();

    foreach ($entries as $entry) {
        $key = $entry['domain_id'] . ':' . $entry['alias_id'];
        $record = isset($records[$key])
            ? $records[$key] : ['dmarc' => NULL, 'dmarc_status' => NULL, 'dkim' => false, 'custom' => false];
        $params = OpenDMARC::effectiveParams($entry['opendmarc_id'] !== NULL ? $entry : [], $defaults);
        $status = $entry['opendmarc_status'];

        $notes = [];
        if ($record['custom']) {
            $notes[] = tr('A _dmarc record defined through your custom DNS records takes precedence. The record below is not published.');
        } elseif ($params['policy'] !== 'none' && !$record['dkim']) {
            $notes[] = tr('No DKIM key is published for this domain: a %s policy can cause your legitimate mail to be junked or rejected if SPF alignment fails.', $params['policy']);
        }
        if ($entry['opendmarc_id'] !== NULL && $entry['policy'] === NULL) {
            $notes[] = tr('Server default policy.');
        }

        $published = $record['dmarc'] !== NULL ? trim(preg_replace('/"\s*"/', '', $record['dmarc']), '"') : '';

        $tpl->assign([
            'DOMAIN_NAME'    => tohtml(decode_idna($entry['name'])),
            'DNS_NAME'       => tohtml('_dmarc.' . decode_idna($entry['name']) . '.'),
            'POLICY'         => tohtml($params['policy']),
            'RECORD'         => tohtml($published !== '' ? $published : tr('N/A')),
            'STATUS'         => tohtml(OpenDMARC::translateStatus($status)),
            'STATUS_ICON'    => tohtml(OpenDMARC::statusIcon($status), 'htmlAttr'),
            'NOTES'          => tohtml(implode(' ', $notes))
        ]);

        if ($canEdit && $entry['opendmarc_id'] !== NULL && !in_array($status, OpenDMARC::$pendingStatuses, true)) {
            $tpl->assign([
                'EDIT_URL' => tohtml('opendmarc_edit?id=' . (int)$entry['opendmarc_id'], 'htmlAttr'),
                'TR_EDIT'  => tohtml(tr('Edit'))
            ]);
            $tpl->parse('DMARC_EDIT_LINK', 'dmarc_edit_link');
        } else {
            $tpl->assign('DMARC_EDIT_LINK', '');
        }

        $tpl->parse('DMARC_ENTRY', '.dmarc_entry');
    }
}

/***********************************************************************************************************************
 * Main
 */

check_login('user');
EventManager::getInstance()->dispatch(Events::onClientScriptStart);

/** @var OpenDMARC $plugin */
$plugin = Registry::get('pluginManager')->pluginGet('OpenDMARC');

$tpl = new TemplateEngine();
$tpl->define_dynamic([
    'layout'          => 'shared/layouts/ui.tpl',
    'page'            => '../../plugins/OpenDMARC/themes/default/view/client/opendmarc.tpl',
    'page_message'    => 'layout',
    'dmarc_entries'   => 'page',
    'dmarc_entry'     => 'dmarc_entries',
    'dmarc_edit_link' => 'dmarc_entry',
    'dmarc_no_entry'  => 'page'
]);

$tpl->assign([
    'TR_PAGE_TITLE'  => tohtml(tr('Client / Domains / DMARC')),
    'TR_TITLE'       => tohtml(tr('DMARC policy records')),
    'TR_HINT'        => tohtml(tr('A DMARC record tells receiving mail servers what to do with mail that claims to come from your domain but fails SPF and DKIM checks. If the DNS zones of your domains are not managed by this server, add the records below at your DNS provider.')),
    'TR_DOMAIN'      => tohtml(tr('Domain')),
    'TR_DNS_NAME'    => tohtml(tr('Name')),
    'TR_POLICY'      => tohtml(tr('Policy')),
    'TR_RECORD'      => tohtml(tr('Published record')),
    'TR_STATUS'      => tohtml(tr('Status')),
    'TR_NOTES'       => tohtml(tr('Notes')),
    'TR_ACTIONS'     => tohtml(tr('Actions'))
]);

generateNavigation($tpl);
opendmarc_generatePage($tpl, $plugin);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventManager::getInstance()->dispatch(Events::onClientScriptEnd, ['templateEngine' => $tpl]);
$tpl->prnt();
