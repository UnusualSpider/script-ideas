#!/usr/bin/env bash
# 01 - Machine & service info. Read-only. Prints to screen and saves a report.
# Usage: 01-machine-info.sh
source "$(dirname "$0")/../lib.sh"
need_root

REPORT="$(outdir reports)/machine-info-$(hostname)-$(stamp).txt"
exec > >(tee "$REPORT") 2>&1

section() { printf '\n%s===== %s =====%s\n' "$C_CYAN" "$1" "$C_RESET"; }

section "SYSTEM"
echo "Hostname : $(hostname -f 2>/dev/null || hostname)"
[[ -r /etc/os-release ]] && . /etc/os-release && echo "OS       : ${PRETTY_NAME:-unknown}"
echo "Kernel   : $(uname -r)  ($(uname -m))"
echo "Uptime   : $(uptime -p 2>/dev/null || uptime)"
echo "CPU      : $(nproc) cores - $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "Memory   : $(free -h | awk '/Mem:/{print $2" total, "$7" available"}')"
echo "Date/TZ  : $(date)  $(timedatectl show -p Timezone --value 2>/dev/null)"
echo "Virt     : $(systemd-detect-virt 2>/dev/null || echo unknown)"

section "NETWORK"
ip -br addr 2>/dev/null || ifconfig -a
echo; echo "Default route:"; ip route show default 2>/dev/null
echo; echo "DNS:"; grep -v '^#' /etc/resolv.conf 2>/dev/null
echo; echo "/etc/hosts (non-default):"; grep -vE '^\s*#|^\s*$|localhost|ip6-' /etc/hosts

section "DISK"
df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null

section "LISTENING PORTS (service -> process)"
if have ss; then ss -tulpnH | awk '{printf "%-5s %-28s %s\n",$1,$5,$7}' | sort -k2 -V
else netstat -tulpn; fi

section "SCORED SERVICES (from config.sh)"
for s in "${CF_SCORED_SERVICES[@]}"; do
    state=$(systemctl is-active "$s" 2>/dev/null); enabled=$(systemctl is-enabled "$s" 2>/dev/null)
    printf '%-20s active=%-10s enabled=%s\n' "$s" "${state:-unknown}" "${enabled:-unknown}"
done

section "RUNNING SERVICES"
systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | column -c 160

section "ENABLED AT BOOT"
systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | awk '{print $1}' | column -c 160

section "FAILED UNITS"
systemctl --failed --no-pager --no-legend 2>/dev/null || true

section "COMMON SERVICE VERSIONS"
for b in sshd apache2 httpd nginx mysqld mariadbd postgres named vsftpd proftpd postfix dovecot smbd php python3 docker; do
    p=$(command -v "$b" 2>/dev/null) || continue
    case $b in
        sshd)    v=$(sshd -V 2>&1 | head -1) ;;
        apache2) v=$(apache2 -v 2>/dev/null | head -1) ;;
        httpd)   v=$(httpd -v 2>/dev/null | head -1) ;;
        nginx)   v=$(nginx -v 2>&1) ;;
        named)   v=$(named -v 2>/dev/null) ;;
        *)       v=$("$b" --version 2>&1 | head -1) ;;
    esac
    printf '%-10s %s\n' "$b" "$v"
done

section "WEB ROOTS / VHOSTS"
for d in /etc/apache2/sites-enabled /etc/httpd/conf.d /etc/nginx/sites-enabled /etc/nginx/conf.d; do
    [[ -d $d ]] && grep -RhiE '^\s*(DocumentRoot|root|server_name|ServerName|listen)\s' "$d" 2>/dev/null | sed "s|^|$d: |"
done

section "DATABASES"
have mysql && echo "MySQL/MariaDB client present"; have psql && echo "PostgreSQL client present"
ls -d /var/lib/mysql /var/lib/pgsql /var/lib/postgresql 2>/dev/null

section "CONTAINERS"
have docker && docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || echo "docker not installed"

section "USERS WITH SHELLS / UID 0"
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1" uid="$3" shell="$7" home="$6}' /etc/passwd
echo "UID 0 accounts: $(awk -F: '$3==0{print $1}' /etc/passwd | xargs)"
echo "sudo/wheel    : $(getent group sudo wheel admin | cut -d: -f4 | xargs)"

section "LOGGED IN / RECENT"
who; echo; last -n 10 2>/dev/null | head -12

section "SECURITY CONTROLS"
echo "SELinux  : $(getenforce 2>/dev/null || echo n/a)"
echo "AppArmor : $(aa-status --enabled 2>/dev/null && echo enabled || echo n/a)"
echo "Firewall : ufw=$(ufw status 2>/dev/null | head -1 | awk '{print $2}') firewalld=$(systemctl is-active firewalld 2>/dev/null) iptables-rules=$(iptables -S 2>/dev/null | grep -c '^-A')"
echo "auditd   : $(systemctl is-active auditd 2>/dev/null)"

echo; good "Report saved: $REPORT"
