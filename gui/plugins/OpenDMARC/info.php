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

return [
    'author'      => 'i-MSCP Debian 13 port',
    'email'       => 'noreply@example.org',
    'version'     => '1.0.0',
    'require_api' => '1.5.1',
    'date'        => '2026-11-03',
    'build'       => '2026110300',
    'name'        => 'OpenDMARC',
    'desc'        => 'DMARC for customer domains: publishes _dmarc DNS policy records (per-domain settings editable by customers) and verifies DMARC on inbound mail through the OpenDMARC milter (Authentication-Results header, optional rejection).',
    'url'         => 'https://tools.ietf.org/html/rfc7489'
];
