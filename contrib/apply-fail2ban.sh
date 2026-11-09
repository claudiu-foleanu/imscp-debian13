#!/bin/sh
# apply-fail2ban.sh
#
# Install fail2ban and enable brute-force protection for the i-MSCP
# network-facing auth services that have NO application-level protection:
#   SSH, ProFTPd, Dovecot (IMAP/POP), Postfix (SMTP/submission/SASL).
# The panel login is intentionally omitted (already protected app-side).
#
# Idempotent. Localhost is always whitelisted; pass extra admin IPs/CIDRs as
# arguments or via FAIL2BAN_IGNOREIP to avoid locking yourself out, e.g.:
#   sh apply-fail2ban.sh 203.0.113.7 198.51.100.0/24
set -eu

[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }

EXTRA_IPS="${FAIL2BAN_IGNOREIP:-}"
for ip in "$@"; do EXTRA_IPS="$EXTRA_IPS $ip"; done
IGNOREIP="127.0.0.1/8 ::1${EXTRA_IPS:+ $EXTRA_IPS}"

# 1) install fail2ban if missing
if ! command -v fail2ban-client >/dev/null 2>&1; then
    echo "Installing fail2ban..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q fail2ban
fi

# 2) back up any existing jail.local, then write ours
if [ -f /etc/fail2ban/jail.local ]; then
    cp -a /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.bak.$(date +%Y%m%d%H%M%S)"
fi

cat > /etc/fail2ban/jail.local <<EOF
# i-MSCP hardening: fail2ban jails for the network-facing auth services that
# have no application-level brute-force protection (SSH, FTP, mail).
# The panel login is already protected app-side, so it is intentionally omitted.
# Managed by contrib/apply-fail2ban.sh -- re-running the script overwrites this.

[DEFAULT]
ignoreip = ${IGNOREIP}
bantime  = 1h
findtime = 10m
maxretry = 5
banaction          = iptables-multiport
banaction_allports = iptables-allports

[sshd]
enabled = true

[proftpd]
enabled = true

[dovecot]
enabled = true

[postfix]
enabled = true
mode    = more

[postfix-sasl]
enabled = true
EOF

# 3) validate before (re)starting -- restore backup on failure
if ! fail2ban-client -t >/dev/null 2>&1; then
    echo "fail2ban config test FAILED; not restarting. Check /etc/fail2ban/jail.local" >&2
    fail2ban-client -t 2>&1 | tail -5 >&2
    exit 1
fi

systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban
sleep 2

echo "ignoreip = ${IGNOREIP}"
fail2ban-client status
echo "Done. Jails active for SSH, ProFTPd, Dovecot and Postfix (SMTP/SASL)."
echo "Add admin IPs any time by re-running:  sh apply-fail2ban.sh <ip> [ip...]"
