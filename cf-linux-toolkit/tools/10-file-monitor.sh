#!/usr/bin/env bash
# 10 - File creation / change monitoring
#   --baseline        Record sha256 + mode/owner of files under CF_WATCH_DIRS (the integrity baseline)
#   --scan            Compare now vs baseline: new, modified, deleted, and permission/owner changes
#   --watch           Live watch with inotify (prints create/modify/move/delete as they happen)
#   --watch-install   systemd service: live inotify watch, events -> $CF_OUT/filemon/events.log + logger
#   --watch-remove
#   --auditd          Load audit rules that record who writes to sensitive paths (ausearch -k cf-...)
# Uses sha256 + stat; no external deps for baseline/scan. --watch needs inotify-tools.
source "$(dirname "$0")/../lib.sh"
need_root
FDIR=$(outdir filemon)
BASE="$FDIR/baseline.tsv"

# skip the noisy/huge trees even if they fall under a watch dir
PRUNE=( -path /proc -o -path /sys -o -path /dev -o -path "$CF_OUT" -o -path '*/node_modules' -o -path '*/.git' )

build_index() {  # prints: sha  mode  owner  size  path
    find "${CF_WATCH_DIRS[@]}" \( "${PRUNE[@]}" \) -prune -o -type f -print 2>/dev/null |
    while IFS= read -r f; do
        s=$(stat -c '%a %U:%G %s' "$f" 2>/dev/null) || continue
        h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1) || h=unreadable
        printf '%s\t%s\t%s\n' "$h" "$s" "$f"
    done
}

baseline() {
    info "Baselining: ${CF_WATCH_DIRS[*]}"
    build_index | sort -t$'\t' -k3 > "$BASE"
    good "Baseline: $(wc -l < "$BASE") files -> $BASE"
}

scan() {
    [[ -f $BASE ]] || { bad "No baseline - run --baseline first"; exit 1; }
    local now; now=$(mktemp); build_index | sort -t$'\t' -k3 > "$now"
    local report="$FDIR/scan-$(stamp).txt"; local n=0
    {
        # by path (field 3 = path): join old/new
        awk -F'\t' 'NR==FNR{o[$3]=$1" "$2; next}{if(!($3 in o)) print "NEW\t"$3"\t"$1}' "$BASE" "$now"
        awk -F'\t' 'NR==FNR{n[$3]=1; next}{if(!($3 in n)) print "DELETED\t"$3}' "$now" "$BASE"
        awk -F'\t' 'NR==FNR{o[$3]=$1"|"$2; next}{k=$1"|"$2; if(($3 in o)&&o[$3]!=k){split(o[$3],a,"|");split(k,b,"|"); typ=(a[1]!=b[1]?"MODIFIED":"PERMS/OWNER"); print typ"\t"$3"\t"a[2]" -> "b[2]}}' "$BASE" "$now"
    } > "$report"
    n=$(wc -l < "$report")
    if [[ $n -eq 0 ]]; then good "No changes since baseline."
    else
        warn "$n change(s):"
        grep -E '^NEW' "$report"      | while IFS=$'\t' read -r _ p _; do bad  "  NEW      $p"; done
        grep -E '^MODIFIED' "$report" | while IFS=$'\t' read -r _ p _; do warn "  MODIFIED $p"; done
        grep -E '^DELETED' "$report"  | while IFS=$'\t' read -r _ p;   do warn "  DELETED  $p"; done
        grep -E '^PERMS' "$report"    | while IFS=$'\t' read -r _ p d; do warn "  PERMS    $p ($d)"; done
        # highlight new executables/scripts in temp dirs
        grep -E '^NEW' "$report" | grep -E '/(tmp|var/tmp|dev/shm)/|\.(sh|py|pl|elf|bin)$' | while IFS=$'\t' read -r _ p _; do bad "  ^ suspicious drop: $p"; done
        info "Full report: $report"
    fi
    rm -f "$now"
}

watch_cmd() {
    have inotifywait || pkg_install inotify-tools || { bad "need inotify-tools"; exit 1; }
    local dirs=(); for d in "${CF_WATCH_DIRS[@]}"; do [[ -d $d ]] && dirs+=("$d"); done
    exec inotifywait -mr -e create -e modify -e moved_to -e delete -e attrib --timefmt '%H:%M:%S' --format '%T %e %w%f' "${dirs[@]}"
}

watch_install() {
    have inotifywait || pkg_install inotify-tools
    cat > /usr/local/sbin/cf-filemon.sh <<EOF
#!/bin/bash
source "$CF_ROOT/config.sh"
dirs=(); for d in "\${CF_WATCH_DIRS[@]}"; do [[ -d \$d ]] && dirs+=("\$d"); done
inotifywait -mr -e create -e modify -e moved_to -e delete -e attrib --timefmt '%F %T' --format '%T %e %w%f' "\${dirs[@]}" |
while read -r line; do
    echo "\$line" >> "$FDIR/events.log"
    case "\$line" in
        *" "/tmp/*|*" "/var/tmp/*|*" "/dev/shm/*|*CREATE*authorized_keys*|*/etc/passwd|*/etc/shadow|*/etc/cron*)
            logger -t cf-filemon "ALERT \$line" ;;
    esac
done
EOF
    chmod +x /usr/local/sbin/cf-filemon.sh
    cat > /etc/systemd/system/cf-filemon.service <<EOF
[Unit]
Description=CyberForce file monitor
After=local-fs.target
[Service]
ExecStart=/usr/local/sbin/cf-filemon.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now cf-filemon.service
    good "Live file monitor running -> $FDIR/events.log  (alerts: journalctl -t cf-filemon)"
}

auditd_rules() {
    have auditctl || pkg_install auditd || { bad "need auditd"; exit 1; }
    cat > /etc/audit/rules.d/cyberforce.rules <<'EOF'
-w /etc/passwd -p wa -k cf-identity
-w /etc/shadow -p wa -k cf-identity
-w /etc/group -p wa -k cf-identity
-w /etc/sudoers -p wa -k cf-sudo
-w /etc/sudoers.d/ -p wa -k cf-sudo
-w /etc/ssh/sshd_config -p wa -k cf-ssh
-w /root/.ssh/ -p wa -k cf-ssh
-w /etc/crontab -p wa -k cf-cron
-w /etc/cron.d/ -p wa -k cf-cron
-w /var/spool/cron/ -p wa -k cf-cron
-w /etc/systemd/system/ -p wa -k cf-persist
-w /bin/ -p wa -k cf-bin
-w /usr/bin/ -p wa -k cf-bin
-w /usr/local/bin/ -p wa -k cf-bin
EOF
    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/cyberforce.rules
    systemctl enable --now auditd
    good "Audit rules loaded. Who touched passwd?  ausearch -k cf-identity -i"
}

case ${1:-} in
    --baseline)      baseline ;;
    --scan)          scan ;;
    --watch)         watch_cmd ;;
    --watch-install) watch_install ;;
    --watch-remove)  systemctl disable --now cf-filemon.service 2>/dev/null; rm -f /etc/systemd/system/cf-filemon.service /usr/local/sbin/cf-filemon.sh; systemctl daemon-reload; good "File monitor removed" ;;
    --auditd)        auditd_rules ;;
    *) sed -n '2,10p' "$0" ;;
esac
