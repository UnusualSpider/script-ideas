#!/usr/bin/env bash
# 05 - User/group snapshot persistence
#   --snapshot           Save passwd/shadow/group/gshadow/sudoers(.d) + per-user info as the known-good state
#   --diff               Show what changed since the snapshot (new users, UID 0, shell/group/sudo changes, password changes)
#   --restore            Put the snapshot files back (asks first; current files are saved)
#   --watchdog-install   systemd timer every minute: alert on drift (logged + wall message)
#   --watchdog-install --enforce   ...and automatically restore the snapshot on drift
#   --watchdog-remove
# Re-run --snapshot after YOU change passwords or users, or the enforcer will undo your change.
source "$(dirname "$0")/../lib.sh"
need_root
SDIR=$(outdir users)
SNAP="$SDIR/snapshot"
FILES=(/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers)

snapshot() {
    rm -rf "$SNAP"; mkdir -p "$SNAP"
    local f; for f in "${FILES[@]}"; do [[ -f $f ]] && cp -a "$f" "$SNAP/"; done
    [[ -d /etc/sudoers.d ]] && cp -a /etc/sudoers.d "$SNAP/sudoers.d"
    # history copy
    tar -czf "$SDIR/snapshot-$(stamp).tar.gz" -C "$SNAP" . 2>/dev/null
    chmod -R go-rwx "$SDIR"
    good "Snapshot saved ($(wc -l < /etc/passwd) users, $(wc -l < /etc/group) groups) in $SNAP"
}

# returns number of findings; prints them
diff_state() {
    local n=0 u
    [[ -f $SNAP/passwd ]] || { bad "No snapshot - run --snapshot first"; return 99; }
    # new / removed users
    while read -r u; do bad "NEW user: $(grep "^$u:" /etc/passwd)"; n=$((n+1)); done < <(comm -13 <(cut -d: -f1 "$SNAP/passwd" | sort) <(cut -d: -f1 /etc/passwd | sort))
    while read -r u; do warn "REMOVED user: $u"; n=$((n+1)); done < <(comm -23 <(cut -d: -f1 "$SNAP/passwd" | sort) <(cut -d: -f1 /etc/passwd | sort))
    # uid 0
    while read -r u; do [[ $u == root ]] || { bad "UID 0 account: $u"; n=$((n+1)); }; done < <(awk -F: '$3==0{print $1}' /etc/passwd)
    # changed passwd lines (uid/gid/home/shell)
    while read -r line; do
        u=${line%%:*}; old=$(grep "^$u:" "$SNAP/passwd")
        [[ -n $old && $old != "$line" ]] && { bad "CHANGED $u: $old  ->  $line"; n=$((n+1)); }
    done < /etc/passwd
    # password hash changes
    if [[ -f $SNAP/shadow ]]; then
        while IFS=: read -r u h _; do
            o=$(grep "^$u:" "$SNAP/shadow" | cut -d: -f2)
            [[ -n $o && $o != "$h" ]] && { warn "PASSWORD changed: $u"; n=$((n+1)); }
            [[ -z $h ]] && { bad "EMPTY password: $u"; n=$((n+1)); }
        done < /etc/shadow
    fi
    # group membership
    while read -r line; do
        g=${line%%:*}; old=$(grep "^$g:" "$SNAP/group")
        [[ -z $old ]] && { bad "NEW group: $line"; n=$((n+1)); continue; }
        [[ $old != "$line" ]] && { bad "GROUP changed: $old  ->  $line"; n=$((n+1)); }
    done < /etc/group
    # sudoers
    if ! cmp -s "$SNAP/sudoers" /etc/sudoers; then bad "/etc/sudoers changed"; diff "$SNAP/sudoers" /etc/sudoers | sed 's/^/    /'; n=$((n+1)); fi
    if [[ -d /etc/sudoers.d ]]; then
        if ! diff -r "$SNAP/sudoers.d" /etc/sudoers.d >/dev/null 2>&1; then
            bad "/etc/sudoers.d changed"; diff -r "$SNAP/sudoers.d" /etc/sudoers.d 2>&1 | sed 's/^/    /'; n=$((n+1)); fi
    fi
    [[ $n -eq 0 ]] && good "No user/group drift since snapshot."
    return $((n > 98 ? 98 : n))
}

restore() {
    local quiet=${1:-0} bk
    bk="$SDIR/pre-restore-$(stamp)"; mkdir -p "$bk"
    local f; for f in "${FILES[@]}"; do [[ -f $f ]] && cp -a "$f" "$bk/"; done
    [[ -d /etc/sudoers.d ]] && cp -a /etc/sudoers.d "$bk/"
    if [[ $quiet -eq 0 ]]; then confirm "Restore users/groups/sudoers from snapshot? (current saved to $bk)" || return; fi
    # kill sessions of users that will disappear
    comm -13 <(cut -d: -f1 "$SNAP/passwd" | sort) <(cut -d: -f1 /etc/passwd | sort) | while read -r u; do
        pkill -KILL -u "$u" 2>/dev/null && warn "Killed processes of rogue user $u"
    done
    for f in passwd shadow group gshadow sudoers; do [[ -f $SNAP/$f ]] && cat "$SNAP/$f" > "/etc/$f"; done
    if [[ -d $SNAP/sudoers.d ]]; then rm -rf /etc/sudoers.d; cp -a "$SNAP/sudoers.d" /etc/sudoers.d; fi
    visudo -c >/dev/null 2>&1 || bad "visudo -c reports a problem - check /etc/sudoers!"
    good "Users/groups/sudoers restored from snapshot (previous state in $bk)"
}

check() {
    diff_state > "$SDIR/last-check.txt" 2>&1; local rc=$?
    [[ $rc -eq 0 || $rc -eq 99 ]] && return 0
    cat "$SDIR/last-check.txt" >> "$CF_LOG"
    wall "CyberForce: user/group drift detected on $(hostname) - see $SDIR/last-check.txt" 2>/dev/null
    logger -t cyberforce "user/group drift detected ($rc findings)"
    [[ -f $SDIR/.enforce ]] && restore 1
}

watchdog_install() {
    [[ -f $SNAP/passwd ]] || snapshot
    if [[ ${ENFORCE:-0} -eq 1 ]]; then touch "$SDIR/.enforce"; warn "ENFORCE mode: drift will be auto-reverted"; else rm -f "$SDIR/.enforce"; fi
    cat > /etc/systemd/system/cf-user-guard.service <<EOF
[Unit]
Description=CyberForce user/group guard
[Service]
Type=oneshot
ExecStart=/bin/bash $CF_ROOT/tools/05-user-snapshot.sh --check
EOF
    cat > /etc/systemd/system/cf-user-guard.timer <<EOF
[Unit]
Description=CyberForce user/group guard every minute
[Timer]
OnBootSec=30
OnUnitActiveSec=60
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now cf-user-guard.timer
    good "User guard running every 60s (logs: $CF_LOG, journalctl -t cyberforce)"
}

ENFORCE=0; for a in "$@"; do [[ $a == --enforce ]] && ENFORCE=1; done
case ${1:-} in
    --snapshot) snapshot ;;
    --diff)     diff_state; exit 0 ;;
    --restore)  restore 0 ;;
    --check)    check ;;
    --watchdog-install) watchdog_install ;;
    --watchdog-remove)  systemctl disable --now cf-user-guard.timer 2>/dev/null; rm -f /etc/systemd/system/cf-user-guard.*; systemctl daemon-reload; good "User guard removed" ;;
    *) sed -n '2,9p' "$0" ;;
esac
