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
 * Get the DMARC entry with the given identifier, if it belongs to the current customer
 *
 * @param int $id OpenDMARC entry unique identifier
 * @param int $customerId Customer unique identifier
 * @return array|false
 */
function opendmarc_getEntry($id, $customerId)
{
    $stmt = exec_query(
        "
            SELECT t1.opendmarc_id, t1.domain_id, IFNULL(t1.alias_id, 0) AS alias_id, t1.domain_name, t1.policy,
                t1.subdomain_policy, t1.pct, t1.adkim, t1.aspf, t1.rua, t1.ruf, t1.opendmarc_status
            FROM opendmarc AS t1
            JOIN domain AS t2 ON(t2.domain_id = t1.domain_id)
            LEFT JOIN domain_aliasses AS t3 ON(t3.alias_id = t1.alias_id)
            WHERE t1.opendmarc_id = ?
            AND t2.domain_admin_id = ?
            AND (t1.alias_id IS NULL OR t3.domain_id = t1.domain_id)
        ",
        [$id, $customerId]
    );

    return $stmt->fetchRow(PDO::FETCH_ASSOC) ?: false;
}

/**
 * Get a POSTed string value
 *
 * @param string $name Field name
 * @return string|null NULL if missing or not a string
 */
function opendmarc_postValue($name)
{
    return isset($_POST[$name]) && is_string($_POST[$name]) ? trim($_POST[$name]) : NULL;
}

/**
 * Parse and validate the POSTed form
 *
 * Select values: 'default' (NULL, use the server default) or an allowed value.
 * Text values (pct, rua, ruf): empty string means 'use the server default'.
 * The 'omit' subdomain policy value means 'no sp= tag'.
 *
 * @return array|false Column values (NULL = default) or FALSE on validation error
 */
function opendmarc_parseForm()
{
    $fields = [];
    foreach (['policy', 'subdomain_policy', 'pct', 'adkim', 'aspf', 'rua', 'ruf'] as $name) {
        $fields[$name] = opendmarc_postValue($name);
        if ($fields[$name] === NULL) {
            showBadRequestErrorPage();
        }
    }

    $values = [];
    $error = false;

    // Selects: whitelist, anything else is a forged request
    if ($fields['policy'] === 'default') {
        $values['policy'] = NULL;
    } elseif (in_array($fields['policy'], OpenDMARC::$policies, true)) {
        $values['policy'] = $fields['policy'];
    } else {
        showBadRequestErrorPage();
    }

    if ($fields['subdomain_policy'] === 'default') {
        $values['subdomain_policy'] = NULL;
    } elseif ($fields['subdomain_policy'] === 'omit') {
        $values['subdomain_policy'] = '';
    } elseif (in_array($fields['subdomain_policy'], OpenDMARC::$policies, true)) {
        $values['subdomain_policy'] = $fields['subdomain_policy'];
    } else {
        showBadRequestErrorPage();
    }

    foreach (['adkim', 'aspf'] as $name) {
        if ($fields[$name] === 'default') {
            $values[$name] = NULL;
        } elseif (in_array($fields[$name], ['r', 's'], true)) {
            $values[$name] = $fields[$name];
        } else {
            showBadRequestErrorPage();
        }
    }

    // Free text: validated
    if ($fields['pct'] === '') {
        $values['pct'] = NULL;
    } elseif (preg_match('/^\d{1,3}\z/', $fields['pct']) && (int)$fields['pct'] >= 1 && (int)$fields['pct'] <= 100) {
        $values['pct'] = (int)$fields['pct'];
    } else {
        set_page_message(tr('The percentage must be an integer between 1 and 100.'), 'error');
        $error = true;
    }

    foreach (['rua' => tr('aggregate report address'), 'ruf' => tr('failure report address')] as $name => $label) {
        if ($fields[$name] === '') {
            $values[$name] = NULL;
        } elseif (OpenDMARC::isValidReportAddress($fields[$name])) {
            $values[$name] = strtolower($fields[$name]);
        } else {
            set_page_message(tr('Invalid %s. Enter a single e-mail address such as dmarc-reports@example.com.', $label), 'error');
            $error = true;
        }
    }

    return $error ? false : $values;
}

/**
 * Update the DMARC settings of the given entry
 *
 * @param array $entry OpenDMARC entry
 * @param array $defaults Server defaults
 * @return bool TRUE on success, FALSE otherwise
 */
function opendmarc_update(array $entry, array $defaults)
{
    if (!OpenDMARC::checkCsrfToken()) {
        showBadRequestErrorPage();
    }

    if (in_array($entry['opendmarc_status'], OpenDMARC::$pendingStatuses, true)) {
        set_page_message(tr('A request is already in progress for this domain. Please retry later.'), 'error');
        return false;
    }

    if (isset($_POST['reset']) && $_POST['reset'] === '1') {
        $values = array_fill_keys(['policy', 'subdomain_policy', 'pct', 'adkim', 'aspf', 'rua', 'ruf'], NULL);
    } elseif (($values = opendmarc_parseForm()) === false) {
        return false;
    }

    // Last check: the resulting record must be valid
    if (OpenDMARC::renderRecord(OpenDMARC::effectiveParams($values, $defaults)) === false) {
        set_page_message(tr('Invalid DMARC settings.'), 'error');
        return false;
    }

    exec_query(
        "
            UPDATE opendmarc
            SET policy = ?, subdomain_policy = ?, pct = ?, adkim = ?, aspf = ?, rua = ?, ruf = ?,
                opendmarc_status = 'tochange'
            WHERE opendmarc_id = ?
        ",
        [
            $values['policy'], $values['subdomain_policy'], $values['pct'], $values['adkim'], $values['aspf'],
            $values['rua'], $values['ruf'], $entry['opendmarc_id']
        ]
    );

    send_request();
    write_log(
        sprintf('DMARC settings of the %s domain have been updated by %s', decode_idna($entry['domain_name']),
            $_SESSION['user_logged']),
        E_USER_NOTICE
    );

    return true;
}

/**
 * Build select options
 *
 * @param array $options Value => label pairs
 * @param string $selected Selected value
 * @return string HTML
 */
function opendmarc_options(array $options, $selected)
{
    $html = '';
    foreach ($options as $value => $label) {
        $html .= '<option value="' . tohtml($value, 'htmlAttr') . '"' . ((string)$value === $selected ? ' selected' : '')
            . '>' . tohtml($label) . '</option>';
    }

    return $html;
}

/**
 * Escape a reflected (user-supplied) value for an HTML attribute
 *
 * Braces are also encoded so that the value can't be interpreted as a
 * template engine variable.
 *
 * @param string $value
 * @return string
 */
function opendmarc_escapeReflected($value)
{
    return str_replace(['{', '}'], ['&#x7b;', '&#x7d;'], tohtml($value, 'htmlAttr'));
}

/**
 * Generate page
 *
 * @param TemplateEngine $tpl
 * @param array $entry OpenDMARC entry
 * @param array $defaults Server defaults
 * @return void
 */
function opendmarc_edit_generatePage(TemplateEngine $tpl, array $entry, array $defaults)
{
    $posted = $_SERVER['REQUEST_METHOD'] === 'POST';
    $current = [];
    foreach (['policy', 'subdomain_policy', 'adkim', 'aspf'] as $name) {
        if ($posted && ($v = opendmarc_postValue($name)) !== NULL) {
            $current[$name] = $v;
        } elseif ($entry[$name] === NULL) {
            $current[$name] = 'default';
        } elseif ($name === 'subdomain_policy' && $entry[$name] === '') {
            $current[$name] = 'omit';
        } else {
            $current[$name] = (string)$entry[$name];
        }
    }
    foreach (['pct', 'rua', 'ruf'] as $name) {
        if ($posted && ($v = opendmarc_postValue($name)) !== NULL) {
            $current[$name] = $v;
        } else {
            $current[$name] = $entry[$name] === NULL ? '' : (string)$entry[$name];
        }
    }

    $policyLabels = [
        'none'       => tr('none (monitoring only)'),
        'quarantine' => tr('quarantine (deliver to junk)'),
        'reject'     => tr('reject')
    ];
    $alignLabels = ['r' => tr('relaxed'), 's' => tr('strict')];
    $defaultSp = isset($policyLabels[$defaults['subdomain_policy']])
        ? $policyLabels[$defaults['subdomain_policy']] : tr('same as policy');
    $defaultAdkim = isset($alignLabels[$defaults['adkim']]) ? $alignLabels[$defaults['adkim']] : $defaults['adkim'];
    $defaultAspf = isset($alignLabels[$defaults['aspf']]) ? $alignLabels[$defaults['aspf']] : $defaults['aspf'];

    $preview = OpenDMARC::renderRecord(OpenDMARC::effectiveParams($entry, $defaults));

    $tpl->assign([
        'FORM_ACTION'             => tohtml('opendmarc_edit?id=' . (int)$entry['opendmarc_id'], 'htmlAttr'),
        'CSRF_TOKEN'              => tohtml(OpenDMARC::getCsrfToken(), 'htmlAttr'),
        'DOMAIN_NAME'             => tohtml(decode_idna($entry['domain_name'])),
        'STATUS'                  => tohtml(OpenDMARC::translateStatus($entry['opendmarc_status'])),
        'RECORD_PREVIEW'          => tohtml($preview !== false ? $preview : tr('N/A')),
        'POLICY_OPTIONS'          => opendmarc_options(
            ['default' => tr('Server default (%s)', $defaults['policy'])] + $policyLabels, $current['policy']
        ),
        'SUBDOMAIN_POLICY_OPTIONS' => opendmarc_options(
            ['default' => tr('Server default (%s)', $defaultSp), 'omit' => tr('Same as policy (no sp tag)')]
            + $policyLabels,
            $current['subdomain_policy']
        ),
        'ADKIM_OPTIONS'           => opendmarc_options(
            ['default' => tr('Server default (%s)', $defaultAdkim)] + $alignLabels, $current['adkim']
        ),
        'ASPF_OPTIONS'            => opendmarc_options(
            ['default' => tr('Server default (%s)', $defaultAspf)] + $alignLabels, $current['aspf']
        ),
        'PCT'                     => opendmarc_escapeReflected($current['pct']),
        'PCT_DEFAULT'             => tohtml($defaults['pct'], 'htmlAttr'),
        'RUA'                     => opendmarc_escapeReflected($current['rua']),
        'RUA_DEFAULT'             => tohtml($defaults['rua'] !== '' ? $defaults['rua'] : tr('no report'), 'htmlAttr'),
        'RUF'                     => opendmarc_escapeReflected($current['ruf']),
        'RUF_DEFAULT'             => tohtml($defaults['ruf'] !== '' ? $defaults['ruf'] : tr('no report'), 'htmlAttr')
    ]);
}

/***********************************************************************************************************************
 * Main
 */

check_login('user');
EventManager::getInstance()->dispatch(Events::onClientScriptStart);

/** @var OpenDMARC $plugin */
$plugin = Registry::get('pluginManager')->pluginGet('OpenDMARC');

if (!$plugin->customerCanEdit() || !isset($_GET['id']) || !is_string($_GET['id']) || !ctype_digit($_GET['id'])) {
    showBadRequestErrorPage();
}

$entry = opendmarc_getEntry((int)$_GET['id'], (int)$_SESSION['user_id']);
if ($entry === false) {
    showNotFoundErrorPage();
}

$defaults = $plugin->getDefaults();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (opendmarc_update($entry, $defaults)) {
        set_page_message(tr('DMARC settings successfully scheduled for update.'), 'success');
        redirectTo('opendmarc');
    }
}

$tpl = new TemplateEngine();
$tpl->define_dynamic([
    'layout'       => 'shared/layouts/ui.tpl',
    'page'         => '../../plugins/OpenDMARC/themes/default/view/client/opendmarc_edit.tpl',
    'page_message' => 'layout'
]);
$tpl->assign([
    'TR_PAGE_TITLE'       => tohtml(tr('Client / Domains / DMARC / Edit')),
    'TR_DOMAIN'           => tohtml(tr('Domain')),
    'TR_DOMAIN_NAME'      => tohtml(tr('Domain name')),
    'TR_STATUS'           => tohtml(tr('Status')),
    'TR_RECORD'           => tohtml(tr('Current settings record')),
    'TR_POLICY'           => tohtml(tr('Policy (p)')),
    'TR_POLICY_TOOLTIP'   => tohtml(tr('What receivers should do with mail failing DMARC. Use quarantine or reject only once all mail sent for this domain is DKIM signed or SPF aligned.'), 'htmlAttr'),
    'TR_SP'               => tohtml(tr('Subdomain policy (sp)')),
    'TR_PCT'              => tohtml(tr('Percentage (pct)')),
    'TR_PCT_TOOLTIP'      => tohtml(tr('Percentage of failing messages to which the policy applies (1-100). Leave empty for the server default.'), 'htmlAttr'),
    'TR_ADKIM'            => tohtml(tr('DKIM alignment (adkim)')),
    'TR_ASPF'             => tohtml(tr('SPF alignment (aspf)')),
    'TR_RUA'              => tohtml(tr('Aggregate reports address (rua)')),
    'TR_RUF'              => tohtml(tr('Failure reports address (ruf)')),
    'TR_REPORT_TOOLTIP'   => tohtml(tr('Single e-mail address. Leave empty for the server default. An address outside of this domain must be authorized by its domain (RFC 7489 section 7.1).'), 'htmlAttr'),
    'TR_UPDATE'           => tohtml(tr('Update'), 'htmlAttr'),
    'TR_RESET'            => tohtml(tr('Reset to server defaults'), 'htmlAttr'),
    'TR_CANCEL'           => tohtml(tr('Cancel'))
]);

generateNavigation($tpl);
opendmarc_edit_generatePage($tpl, $entry, $defaults);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventManager::getInstance()->dispatch(Events::onClientScriptEnd, ['templateEngine' => $tpl]);
$tpl->prnt();
