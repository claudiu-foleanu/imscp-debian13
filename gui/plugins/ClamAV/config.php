<?php
/**
 * i-MSCP ClamAV plugin
 * Copyright (C) 2014-2017 Laurent Declercq <l.declercq@nuxwin.com>
 * Copyright (C) 2013-2017 Rene Schuster <mail@reneschuster.de>
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

return array(
    // Postfix smtpd milter for ClamAV (default: unix:/clamav/clamav-milter.ctl)
    //
    // Possible values:
    //  unix:/clamav/clamav-milter.ctl for connection through UNIX socket
    //  inet:localhost:32767 for connection through TCP
    //
    // Note: The Postfix smtpd(8) and cleanup(8) services run chrooted
    // (/var/spool/postfix) on Debian. UNIX socket paths are therefore relative
    // to the Postfix queue directory and the clamav-milter socket MUST be
    // located under /var/spool/postfix (see the MilterSocket option below).
    'PostfixMilterSocket'            => 'unix:/clamav/clamav-milter.ctl',

    // Postfix per-milter default action, applied when the ClamAV milter is
    // unavailable (default: tempfail)
    //
    // The action is set on the milter entry itself, e.g:
    //  smtpd_milters = { unix:/clamav/clamav-milter.ctl, default_action=tempfail }
    // so that the global Postfix milter_default_action parameter, which is
    // shared with other milter plugins (OpenDKIM, SpamAssassin...), is left
    // untouched.
    //
    // Possible values: accept, reject, tempfail, quarantine (see postconf(5))
    'PostfixMilterDefaultAction'     => 'tempfail',

    // The following configuration options are added in the /etc/clamav/clamav-milter.conf file
    //
    // Note: If an options is missing, just add it with it name and it will be automatically added.
    //
    // See man clamav-milter.conf for further details about available options.
    //
    'clamav_milter_options'          => array(
        // Milter socket (default: /var/spool/postfix/clamav/clamav-milter.ctl)
        //
        // Possible values:
        // /var/spool/postfix/clamav/clamav-milter.ctl for connection through UNIX socket
        //  inet:32767@localhost for connection through TCP
        'MilterSocket'              => '/var/spool/postfix/clamav/clamav-milter.ctl',
        // Milter socket group and mode
        //
        // The socket is only made accessible to the Postfix user (smtpd(8) and
        // cleanup(8) services) through its primary group. Don't make it
        // world-accessible (666): any local user could then talk to the
        // milter.
        'MilterSocketGroup'         => 'postfix',
        'MilterSocketMode'          => '660',
        'FixStaleSocket'            => 'true',
        'User'                      => 'clamav',
        'ReadTimeout'               => '120',
        'Foreground'                => 'false',
        'PidFile'                   => '/run/clamav/clamav-milter.pid',
        'TemporaryDirectory'        => '/tmp',

        // Clamd options
        'ClamdSocket'               => 'unix:/run/clamav/clamd.ctl',

        // Exclusions options
        //
        // Messages larger than MaxFileSize are NOT scanned and are accepted
        // as is (policy choice: scanning large messages is costly). Make sure
        // that this value is lower or equal than the clamd.conf StreamMaxLength
        // value, and consider raising it up to the Postfix message_size_limit
        // value if you want all messages to be scanned.
        'MaxFileSize'               => '25M',

        // Actions options
        'OnClean'                   => 'Accept',
        'OnInfected'                => 'Reject',
        'OnFail'                    => 'Defer',
        'RejectMsg'                 => 'Blocked by ClamAV - FOUND VIRUS: %v',
        'AddHeader'                 => 'Replace',
        'VirusAction'               => '',

        // Logging options
        'LogFile'                   => '/var/log/clamav/clamav-milter.log',
        'LogFileUnlock'             => 'false',
        'LogFileMaxSize'            => '0M',
        'LogTime'                   => 'true',
        'LogSyslog'                 => 'true',
        'LogFacility'               => 'LOG_MAIL',
        'LogVerbose'                => 'false',
        'LogInfected'               => 'Basic',
        'LogClean'                  => 'Off',
        'LogRotate'                 => 'true',
        'SupportMultipleRecipients' => 'false'
    ),

    // 3rd party ClamAV Unofficial Signatures - clamav-unofficial-sigs (bundled version: 8.0.0)
    //
    // https://github.com/extremeshok/clamav-unofficial-sigs
    //
    // The clamav-unofficial-sigs script provides a simple way to download, test, and update
    // third-party signature databases provided by Sanesecurity, SecuriteInfo, MalwarePatrol,
    // InterServer, URLhaus, Linux Malware Detect, etc.
    //
    // Warning: Don't change anything if you don't know what you are doing.
    //
    'clamav_unofficial_sigs_options' => array(
        // Enable ClamAV Unofficial Signatures (default: yes)
        'clamav_unofficial_sigs' => 'yes',

        // MalwarePatrol (free) clamav signatures: https://www.malwarepatrol.net
        //
        // 1. Sign up for a free account: https://www.malwarepatrol.net/free-guard-upgrade-option/
        // 2. You will recieve an email containing your password/receipt number
        // 3. Login to your account at MalwarePatrol
        // 4. In My Accountpage, choose the ClamAV list you will download. Free subscribers only get ClamAV Basic,
        //    commercial subscribers have access to ClamAV Extended. Do not use the agressive lists.
        // 5. In the download URL, you will see 3 parameters: receipt, product and list, enter them in the variables below.
        //
        // The MalwarePatrol databases are skipped as long as the receipt code is not set.
        'malwarepatrol_options'  => array(
            'malwarepatrol_receipt_code' => 'YOUR-RECEIPT-NUMBER',
            'malwarepatrol_product_code' => '32',
            'malwarepatrol_list'         => 'clamav_basic',  // clamav_basic or clamav_ext
            'malwarepatrol_free'         => 'yes'            // set to 'no' to enable the commercial subscription url
        ),

        // SecuriteInfo free clamav signatures: https://www.securiteinfo.com
        //
        // 1. Sign up for a free account: https://www.securiteinfo.com/clients/customers/signup
        // 2. You will recieve an email to activate your account and then a followup email with your login name
        // 3. Login and navigate to your customer account: https://www.securiteinfo.com/clients/customers/account
        // 4. Click on the Setup tab
        // 5. You will need to get your unique identifier from one of the download links, they are individual for every user
        //    The 128 character string is after the http://www.securiteinfo.com/get/signatures/
        //    Example https://www.securiteinfo.com/get/signatures/your_unique_and_very_long_random_string_of_characters/securiteinfo.hdb
        //    Your 128 character authorisation signature would be : your_unique_and_very_long_random_string_of_characters
        // 6. Enter the authorisation signature into the config securiteinfo_authorisation_signature: replacing
        //    YOUR-SIGNATURE-NUMBER with your authorisation signature from the link
        //
        // The SecuriteInfo databases are skipped as long as the authorisation signature is not set.
        'securiteinfo_options'   => array(
            'securiteinfo_authorisation_signature' => 'YOUR-SIGNATURE-NUMBER',
        ),

        // Signatures enabled
        // Set to 'no' to disable an entire set of signatures
        'signatures_enabled'     => array(
            'sanesecurity_enabled'       => 'yes',
            'securiteinfo_enabled'       => 'yes',
            'linuxmalwaredetect_enabled' => 'yes',
            'malwarepatrol_enabled'      => 'yes',
            'interserver_enabled'        => 'yes',
            'urlhaus_enabled'            => 'yes',
            // DEPRECATED upstream: the Yara-Rules repository is unmaintained and several rules fail
            // to load or crash ClamAV >= 1.0. Enable at your own risk.
            'yararulesproject_enabled'   => 'no'
        ),

        // Rating (False Positive Rating)
        //
        // By default only signature databases with 'LOW' false positive risk are enabled.
        //
        // Valid ratings: LOW, MEDIUM, HIGH, DISABLE
        //
        // Warning: Don't change anything if you don't know what you are doing.
        //
        'rating_options'         => array(
            'default_dbs_rating'            => 'LOW',
            'sanesecurity_dbs_rating'       => 'LOW',
            'securiteinfo_dbs_rating'       => 'LOW',
            'linuxmalwaredetect_dbs_rating' => 'LOW',
            'urlhaus_dbs_rating'            => 'LOW'
        )
    )
);
