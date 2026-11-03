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

/*
 * Per-domain DMARC settings. A NULL value means "use the server-wide default
 * from config.php". An empty subdomain_policy means "omit the sp= tag" and an
 * empty rua/ruf means "no report requested".
 *
 * alias_id is NULL for main domains. Rows are removed with their domain or
 * domain alias (ON DELETE CASCADE).
 */
return [
    'up'   => '
        CREATE TABLE IF NOT EXISTS opendmarc (
            opendmarc_id int(10) unsigned NOT NULL AUTO_INCREMENT,
            domain_id int(10) unsigned NOT NULL,
            alias_id int(10) unsigned DEFAULT NULL,
            domain_name varchar(255) NOT NULL,
            policy varchar(10) DEFAULT NULL,
            subdomain_policy varchar(10) DEFAULT NULL,
            pct tinyint(3) unsigned DEFAULT NULL,
            adkim char(1) DEFAULT NULL,
            aspf char(1) DEFAULT NULL,
            rua varchar(255) DEFAULT NULL,
            ruf varchar(255) DEFAULT NULL,
            opendmarc_status text NOT NULL,
            PRIMARY KEY (opendmarc_id),
            UNIQUE KEY domain_name (domain_name(191)),
            KEY domain_id (domain_id),
            KEY alias_id (alias_id),
            CONSTRAINT opendmarc_domain_id_fk FOREIGN KEY (domain_id) REFERENCES domain (domain_id) ON DELETE CASCADE,
            CONSTRAINT opendmarc_alias_id_fk FOREIGN KEY (alias_id) REFERENCES domain_aliasses (alias_id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ',
    'down' => 'DROP TABLE IF EXISTS opendmarc'
];
