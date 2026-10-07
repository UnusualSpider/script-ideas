#!/usr/bin/env bash
# 06 - Cronjob nuke
#   (no args)   List every scheduled job: user crontabs, /etc/crontab, cron.d, cron.{hourly,daily,weekly,monthly},
#               at jobs, systemd timers, anacron - flags ones not owned by a package and suspicious commands
#   --nuke      Back up everything, then:
#                 - empty every user crontab (except CF_EXCLUDED_USERS)
#                 - quarantine NON-package files from /etc/cron.d and /etc/cron.* dirs
#                 - remove all at jobs
#                 - disable + quarantine non-package systemd timers in /etc/systemd/system
#   --lock      Only root may use cron/at from now on (writes cron.allow / at.allow)
#   --restore DIR   Put back a previous nuke backup
# Package-owned jobs (logrotate, apt, etc.) are left alone.
source "$(dirname "$0")/../lib.sh"
need_root

SUS='(curl|wget|nc |ncat|netcat|socat|bash -i|sh -i|/dev/tcp|/dev/udp|python[0-9.]* -c|perl -e|base64|mkfifo|chmod \+s|/tmp/|/dev/shm|/var/tmp|useradd|passwd|authorized_keys|iptables -F|nft flush)'

owned() {  # is file owned by a package?
    if have dpkg; then dpkg -S "$1" >/dev/null 2>&1
    elif have rpm; then rpm -qf "$1" >/dev/null 2>&1
    else return 1; fi
}

flag_lines() { # file
    grep -vE '^\s*(#|$)' "$1" 2>/dev/null | while IFS= read -r l; do
        if [[ $l =~ $SUS ]]; then bad "    SUSPICIOUS: $l"; else echo "    $l"; fi
    done
}

spool_dirs() { for d in /var/spool/cron/crontabs /var/spool/cron; do [[ -d $d ]] && echo "$d"; done; }

list_all() {
    info "== User crontabs =="
    for d in $(spool_dirs); do
        for f in "$d"/*; do [[ -f $f ]] || continue; warn "  $f"; flag_lines "$f"; done
    done
    info "== /etc/crontab =="; flag_lines /etc/crontab
    info "== /etc/cron.d and cron.{hourly,daily,weekly,monthly} =="
    for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        [[ -f $f ]] || continue
        if owned "$f"; then echo "  [pkg] $f"; else warn "  [NOT PACKAGED] $f"; flag_lines "$f"; fi
    done
    info "== at jobs =="; have atq && atq || echo "  (at not installed)"
    info "== systemd timers =="
    systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print "  "$0}'
    for f in /etc/systemd/system/*.timer /etc/systemd/system/*/*.timer; do
        [[ -f $f ]] || continue
        [[ $(basename "$f") == cf-* ]] && continue
        owned "$f" || warn "  [NOT PACKAGED timer] $f -> $(grep -h '^ExecStart' "${f%.timer}.service" 2>/dev/null)"
    done
    [[ -f /etc/anacrontab ]] && { info "== anacrontab =="; flag_lines /etc/anacrontab; }
}

nuke() {
    local bk; bk="$(outdir cron)/nuke-$(stamp)"; mkdir -p "$bk/spool" "$bk/etc" "$bk/timers"
    info "Backing up to $bk"
    [[ -d /var/spool/cron ]] && cp -a /var/spool/cron/. "$bk/spool/"
    cp -a /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly "$bk/etc/" 2>/dev/null
    have atq && atq > "$bk/atq.txt"

    # user crontabs
    for d in $(spool_dirs); do
        for f in "$d"/*; do
            [[ -f $f ]] || continue; u=$(basename "$f")
            if is_excluded "$u"; then info "Kept crontab of excluded user $u"; continue; fi
            crontab -r -u "$u" 2>/dev/null || rm -f "$f"; good "Cleared crontab: $u"
        done
    done
    # non-package system cron files
    for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        [[ -f $f ]] || continue
        owned "$f" && continue
        [[ $(basename "$f") == .placeholder ]] && continue
        mkdir -p "$bk/quarantine$(dirname "$f")"; mv "$f" "$bk/quarantine$f"; good "Quarantined $f"
    done
    # suspicious lines in /etc/crontab are commented out, not deleted
    if grep -qE "$SUS" /etc/crontab; then
        sed -i -E "/^\s*#/!{/$SUS/s/^/#CF-NUKED# /}" /etc/crontab; good "Commented suspicious lines in /etc/crontab"
    fi
    # at jobs
    if have atq; then for j in $(atq | awk '{print $1}'); do atrm "$j" && good "Removed at job $j"; done; fi
    # non-package timers
    for f in /etc/systemd/system/*.timer; do
        [[ -f $f ]] || continue; n=$(basename "$f")
        [[ $n == cf-* ]] && continue
        owned "$f" && continue
        systemctl disable --now "$n" 2>/dev/null
        mv "$f" "$bk/timers/"; [[ -f ${f%.timer}.service ]] && mv "${f%.timer}.service" "$bk/timers/"
        good "Disabled + quarantined timer $n"
    done
    systemctl daemon-reload
    systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null
    good "Nuke complete. Backup/quarantine: $bk   (undo: $0 --restore $bk)"
}

lock() {
    echo root > /etc/cron.allow; echo root > /etc/at.allow
    chmod 600 /etc/cron.allow /etc/at.allow
    rm -f /etc/cron.deny /etc/at.deny
    good "Only root can schedule cron/at jobs now. Add excluded service users to /etc/cron.allow if the rules need them."
}

restore() {
    local bk=$1; [[ -d $bk ]] || { bad "No such backup dir"; exit 1; }
    confirm "Restore cron state from $bk?" || exit 0
    [[ -d $bk/spool ]] && cp -a "$bk/spool/." /var/spool/cron/
    cp -a "$bk/etc/." /etc/
    [[ -d $bk/quarantine ]] && cp -a "$bk/quarantine/." /
    for t in "$bk"/timers/*; do [[ -f $t ]] && cp -a "$t" /etc/systemd/system/; done
    systemctl daemon-reload
    good "Restored. Re-enable timers by hand if needed: systemctl enable --now NAME.timer"
}

case ${1:-} in
    "")        list_all ;;
    --nuke)    list_all; echo; confirm "NUKE all non-package scheduled jobs listed above?" && nuke ;;
    --yes-nuke) nuke ;;   # non-interactive
    --lock)    lock ;;
    --restore) restore "$2" ;;
    *) sed -n '2,12p' "$0" ;;
esac
