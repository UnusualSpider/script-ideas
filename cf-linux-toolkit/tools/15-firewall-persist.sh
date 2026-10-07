#!/usr/bin/env bash
# 15 - Persistent firewall: make the rules from 07-firewall.sh survive reboots,
# and (optionally) a watchdog that re-applies them if something flushes the tables.
#   --install        Save current iptables/ip6tables rules and restore them at every boot
#                     (uses netfilter-persistent/iptables-save+systemd, whichever fits the distro)
#   --save           Re-save the CURRENT live rules as the ones to restore (do this after any change)
#   --watchdog       systemd timer (every 60s): if the CF-IN chain is gone, re-apply saved rules
#   --watchdog-remove
#   --remove         Stop persisting (does NOT flush current live rules)
# Run 07-firewall.sh --apply FIRST, confirm you still have access, THEN run this.
source "$(dirname "$0")/../lib.sh"
need_root

RULES_V4=/etc/cyberforce/rules.v4
RULES_V6=/etc/cyberforce/rules.v6
mkdir -p /etc/cyberforce

save_rules() {
    iptables-save > "$RULES_V4"; good "Saved IPv4 rules -> $RULES_V4"
    if have ip6tables-save; then ip6tables-save > "$RULES_V6"; good "Saved IPv6 rules -> $RULES_V6"; fi
}

install_persist() {
    iptables -nL CF-IN >/dev/null 2>&1 || warn "CF-IN chain not present - did you run 07-firewall.sh --apply? Saving whatever is live."
    save_rules
    detect_pm
    if [[ $PM == apt ]] && { have netfilter-persistent || pkg_install iptables-persistent netfilter-persistent; }; then
        mkdir -p /etc/iptables
        cp "$RULES_V4" /etc/iptables/rules.v4; [[ -f $RULES_V6 ]] && cp "$RULES_V6" /etc/iptables/rules.v6
        systemctl enable netfilter-persistent >/dev/null 2>&1
        netfilter-persistent save >/dev/null 2>&1
        good "netfilter-persistent will restore rules at boot"
        return
    fi
    # Generic systemd restore unit (works everywhere with iptables-restore)
    cat > /etc/systemd/system/cf-firewall.service <<EOF
[Unit]
Description=CyberForce firewall (restore saved iptables rules)
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'iptables-restore < $RULES_V4'
ExecStart=/bin/sh -c '[ -f $RULES_V6 ] && ip6tables-restore < $RULES_V6 || true'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable cf-firewall.service >/dev/null 2>&1
    good "cf-firewall.service will restore rules at boot"
}

watchdog() {
    [[ -f $RULES_V4 ]] || save_rules
    cat > /usr/local/sbin/cf-fw-watch.sh <<EOF
#!/bin/sh
# re-apply saved rules if the CF-IN chain disappears (attacker flushed iptables)
if ! iptables -nL CF-IN >/dev/null 2>&1; then
    logger -t cf-firewall "CF-IN chain missing - restoring saved rules"
    iptables-restore < $RULES_V4
    [ -f $RULES_V6 ] && ip6tables-restore < $RULES_V6
fi
EOF
    chmod +x /usr/local/sbin/cf-fw-watch.sh
    cat > /etc/systemd/system/cf-fw-watch.service <<EOF
[Unit]
Description=CyberForce firewall watchdog
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cf-fw-watch.sh
EOF
    cat > /etc/systemd/system/cf-fw-watch.timer <<EOF
[Unit]
Description=CyberForce firewall watchdog every minute
[Timer]
OnBootSec=45
OnUnitActiveSec=60
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now cf-fw-watch.timer
    good "Firewall watchdog active (re-applies rules within 60s of a flush). Re-run --save after you change rules."
}

case ${1:-} in
    --install)         install_persist ;;
    --save)            save_rules ;;
    --watchdog)        watchdog ;;
    --watchdog-remove) systemctl disable --now cf-fw-watch.timer 2>/dev/null; rm -f /etc/systemd/system/cf-fw-watch.* /usr/local/sbin/cf-fw-watch.sh; systemctl daemon-reload; good "Watchdog removed" ;;
    --remove)          systemctl disable --now cf-firewall.service 2>/dev/null; rm -f /etc/systemd/system/cf-firewall.service; systemctl daemon-reload; have netfilter-persistent && systemctl disable netfilter-persistent 2>/dev/null; good "Persistence removed (live rules untouched)" ;;
    *) sed -n '2,11p' "$0" ;;
esac
