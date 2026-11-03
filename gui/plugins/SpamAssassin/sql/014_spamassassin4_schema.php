<?php
/**
 * i-MSCP SpamAssassin plugin
 * Copyright (C) 2015-2017 Laurent Declercq <l.declercq@nuxwin.com>
 * Copyright (C) 2013-2016 Sascha Bay <info@space2place.de>
 * Copyright (C) 2013-2016 Rene Schuster <mail@reneschuster.de>
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

/*
 * SpamAssassin 4.0 / MariaDB >= 10.5 (Debian 13) schema update
 *
 * - Switch to utf8mb4
 * - AWL table: `count' and `last_update' columns were renamed to `msgcount'
 *   and `last_hit' (SpamAssassin >= 3.4.2); `email' is a binary string
 * - Bayes tables: `token' and `msgid' are binary strings. The previous schema
 *   stored the binary Bayes tokens in an utf8 case-insensitive column, which
 *   either corrupted tokens (non-strict SQL mode) or made Bayes learning fail
 *   (strict SQL mode, default since MariaDB 10.2.4). The Bayes data being
 *   unusable, the Bayes tables are emptied.
 * - Remove the bogus `use razor2' global preference (typo in 012 migration)
 */

$saDb = quoteIdentifier(iMSCP_Registry::get('config')->DATABASE_NAME . '_spamassassin');

return array(
    'up' => "
        ALTER DATABASE $saDb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

        ALTER TABLE $saDb.awl CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        ALTER TABLE $saDb.awl
            CHANGE COLUMN IF EXISTS `count` `msgcount` int(11) NOT NULL DEFAULT '0',
            CHANGE COLUMN IF EXISTS `last_update` `last_hit` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
        ALTER TABLE $saDb.awl MODIFY `email` varbinary(255) NOT NULL DEFAULT '';

        DELETE FROM $saDb.bayes_token;
        DELETE FROM $saDb.bayes_seen;
        DELETE FROM $saDb.bayes_expire;
        DELETE FROM $saDb.bayes_vars;

        ALTER TABLE $saDb.bayes_token CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        ALTER TABLE $saDb.bayes_token MODIFY `token` binary(5) NOT NULL DEFAULT '';
        ALTER TABLE $saDb.bayes_seen CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        ALTER TABLE $saDb.bayes_seen MODIFY `msgid` varbinary(200) NOT NULL DEFAULT '';
        ALTER TABLE $saDb.bayes_expire CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        ALTER TABLE $saDb.bayes_global_vars CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        ALTER TABLE $saDb.bayes_vars CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        ALTER TABLE $saDb.userpref CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

        DELETE FROM $saDb.userpref WHERE username = '\$GLOBAL' AND preference = 'use razor2';
    "
);
