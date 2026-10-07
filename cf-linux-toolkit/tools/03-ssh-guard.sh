#!/usr/bin/env bash
# 03 - Persistent SSH (blue-team side): keep YOUR access alive and the Red team's out.
#
#   --harden            Apply hardened sshd settings (validated with sshd -t, auto-rollback)
#   --restrict-users    Also add AllowUsers from CF_SSH_ALLOWED_USERS (check scoring needs first!)
#   --add-key FILE      Install a team public key for every CF_SSH_ALLOWED_USERS account
#   --audit-keys        List every authorized_keys entry on the box, flag ones not in the approved set
#   --purge-keys        Remove authorized_keys entries that are not approved (backs up first)
#   --snapshot          Save current sshd config + approved keys as the "known good" state
#   --watchdog-install  systemd timer (every minute): sshd running, config + keys restored if tampered
#   --watchdog-remove   Remove the watchdog
#   --check             One-shot of what the watchdog does
# Approved keys live in $CF_OUT/ssh/approved_keys (one key per line).
source "$(dirname "$0")/../lib.sh"
need_root

SSHD=$(svc_name_ssh)
SDIR=$(outdir ssh)
GOOD="$SDIR/known-good"
APPROVED="$SDIR/approved_keys"
DROPIN=/etc/ssh/sshd_config.d/00-cyberforce.conf
mkdir -p "$GOOD"; touch "$APPROVED"; chmod 600 "$APPROVED"

home_of() { getent passwd "$1" | cut -d: -f6; }

harden_block() {
    cat <<EOF
# --- CyberForce hardening (managed by 03-ssh-guard.sh) ---
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
HostbasedAuthentication no
IgnoreRhosts yes
LogLevel VERBOSE
EOF
    if [[ ${RESTRICT:-0} -eq 1 ]]; then echo "AllowUsers ${CF_SSH_ALLOWED_USERS[*]}"; fi
    echo "# --- end CyberForce ---"
}

do_harden() {
    local bk; bk="$SDIR/sshd_config.$(stamp).bak"
    cp -a /etc/ssh/sshd_config "$bk"
    [[ -f $DROPIN ]] && cp -a "$DROPIN" "$bk.dropin"
    if grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
        harden_block > "$DROPIN"; chmod 600 "$DROPIN"
        info "Wrote $DROPIN"
    else
        # No Include support - sshd uses the FIRST value seen, so prepend the block
        sed -i '/# --- CyberForce hardening/,/# --- end CyberForce ---/d' /etc/ssh/sshd_config
        { harden_block; cat /etc/ssh/sshd_config; } > /etc/ssh/sshd_config.new && mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
        info "Prepended hardening block to /etc/ssh/sshd_config"
    fi
    if sshd -t 2>"$SDIR/sshd-t.err"; then
        systemctl reload "$SSHD" 2>/dev/null || systemctl restart "$SSHD"
        good "sshd hardened and reloaded (backup: $bk). Existing sessions stay open - test a NEW login now."
    else
        bad "sshd -t failed - rolling back: $(cat "$SDIR/sshd-t.err")"
        cp -a "$bk" /etc/ssh/sshd_config; [[ -f $bk.dropin ]] && cp -a "$bk.dropin" "$DROPIN" || rm -f "$DROPIN"
    fi
    grep -iE '^\s*PermitRootLogin|^\s*PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null |
        sed 's/^/  current: /'
    info "PermitRootLogin / PasswordAuthentication left as-is - scoring may log in with passwords. Change by hand if the rules allow."
}

add_key() {
    local f=$1 u h
    [[ -s $f ]] || { bad "Key file $f missing/empty"; exit 1; }
    grep -E '^(ssh-|ecdsa-|sk-)' "$f" >> "$APPROVED"; sort -u -o "$APPROVED" "$APPROVED"
    for u in "${CF_SSH_ALLOWED_USERS[@]}"; do
        h=$(home_of "$u") || continue; [[ -n $h ]] || continue
        install -d -m 700 -o "$u" -g "$(id -gn "$u")" "$h/.ssh"
        touch "$h/.ssh/authorized_keys"
        while read -r k; do grep -qxF "$k" "$h/.ssh/authorized_keys" || echo "$k" >> "$h/.ssh/authorized_keys"; done < "$f"
        chown "$u:$(id -gn "$u")" "$h/.ssh/authorized_keys"; chmod 600 "$h/.ssh/authorized_keys"
        good "Team key installed for $u"
    done
}

key_files() {
    getent passwd | while IFS=: read -r u _ _ _ _ h _; do
        for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do [[ -f $f ]] && echo "$u:$f"; done
    done
    # AuthorizedKeysFile pointed somewhere unusual?
    grep -hiE '^\s*AuthorizedKeys(File|Command)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null |
        sed 's/^/NOTE: sshd uses /' >&2
}

audit_keys() {
    local purge=${1:-0} bad_n=0
    if [[ $purge -eq 1 && ! -s $APPROVED ]]; then
        bad "Approved key list is empty - purging would delete EVERY key. Add your team key first (--add-key)."; return 1
    fi
    while IFS=: read -r u f; do
        while IFS= read -r line; do
            [[ -z $line || $line == \#* ]] && continue
            if grep -qxF "$line" "$APPROVED"; then
                good "$u  approved   ${line:0:40}... ${line##* }"
            else
                bad "$u  UNKNOWN    ${line:0:40}... ${line##* }  ($f)"; bad_n=$((bad_n+1))
            fi
        done < "$f"
        if [[ $purge -eq 1 ]]; then
            cp -a "$f" "$SDIR/$(echo "$f" | tr / _).$(stamp).bak"
            grep -xFf "$APPROVED" "$f" > "$f.cf" 2>/dev/null || true
            cat "$f.cf" > "$f"; rm -f "$f.cf"
            info "Purged unapproved keys from $f (backup in $SDIR)"
        fi
    done < <(key_files)
    [[ $bad_n -eq 0 ]] && good "No unapproved keys." || warn "$bad_n unapproved key(s). Use --purge-keys to remove."
}

snapshot() {
    cp -a /etc/ssh/sshd_config "$GOOD/sshd_config"
    rm -rf "$GOOD/sshd_config.d"; [[ -d /etc/ssh/sshd_config.d ]] && cp -a /etc/ssh/sshd_config.d "$GOOD/"
    rm -rf "$GOOD/keys"; mkdir -p "$GOOD/keys"; : > "$GOOD/keys.map"
    local n=0
    while IFS=: read -r u f; do
        n=$((n+1)); cp -a "$f" "$GOOD/keys/$n"; printf '%s\t%s\n' "$n" "$f" >> "$GOOD/keys.map"
    done < <(key_files 2>/dev/null)
    good "Known-good SSH state saved in $GOOD"
}

check() {
    # 1. sshd running
    if ! systemctl is-active -q "$SSHD"; then
        warn "sshd was DOWN - restarting"; systemctl enable --now "$SSHD"
    fi
    # 2. config tampering
    if [[ -f $GOOD/sshd_config ]] && ! cmp -s "$GOOD/sshd_config" /etc/ssh/sshd_config; then
        bad "sshd_config changed! Saving tampered copy and restoring known-good"
        cp -a /etc/ssh/sshd_config "$SDIR/tampered-sshd_config.$(stamp)"
        cp -a "$GOOD/sshd_config" /etc/ssh/sshd_config
        rm -rf /etc/ssh/sshd_config.d; [[ -d $GOOD/sshd_config.d ]] && cp -a "$GOOD/sshd_config.d" /etc/ssh/
        sshd -t && systemctl reload "$SSHD"
    fi
    # 3. unknown keys -> strip if we have an approved list
    if [[ -s $APPROVED ]]; then
        while IFS=: read -r u f; do
            if grep -vxFf "$APPROVED" "$f" | grep -qE '^(ssh-|ecdsa-|sk-|[a-z-]+=.*ssh-)'; then
                bad "Unapproved key appeared in $f - removing"
                cp -a "$f" "$SDIR/tampered$(echo "$f" | tr / _).$(stamp)"
                grep -xFf "$APPROVED" "$f" > "$f.cf" || true; cat "$f.cf" > "$f"; rm -f "$f.cf"
            fi
        done < <(key_files 2>/dev/null)
    fi
    # 4. allowed users' own keys restored if deleted
    if [[ -f $GOOD/keys.map ]]; then
        while IFS=$'\t' read -r n f; do
            [[ -f $f ]] || { warn "$f deleted - restoring"; mkdir -p "$(dirname "$f")"; cp -a "$GOOD/keys/$n" "$f"; }
        done < "$GOOD/keys.map"
    fi
}

watchdog_install() {
    [[ -f $GOOD/sshd_config ]] || snapshot
    cat > /etc/systemd/system/cf-ssh-guard.service <<EOF
[Unit]
Description=CyberForce SSH guard
[Service]
Type=oneshot
ExecStart=/bin/bash $CF_ROOT/tools/03-ssh-guard.sh --check
EOF
    cat > /etc/systemd/system/cf-ssh-guard.timer <<EOF
[Unit]
Description=CyberForce SSH guard every minute
[Timer]
OnBootSec=30
OnUnitActiveSec=60
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now cf-ssh-guard.timer
    good "SSH watchdog running every 60s (journalctl -u cf-ssh-guard)"
}

[[ $# -eq 0 ]] && { sed -n '2,15p' "$0"; exit 0; }
RESTRICT=0
for a in "$@"; do [[ $a == --restrict-users ]] && RESTRICT=1; done
while [[ $# -gt 0 ]]; do
    case $1 in
        --harden) do_harden ;;
        --restrict-users) ;;
        --add-key) add_key "$2"; shift ;;
        --audit-keys) audit_keys 0 ;;
        --purge-keys) audit_keys 1 ;;
        --snapshot) snapshot ;;
        --watchdog-install) watchdog_install ;;
        --watchdog-remove) systemctl disable --now cf-ssh-guard.timer 2>/dev/null; rm -f /etc/systemd/system/cf-ssh-guard.*; systemctl daemon-reload; good "Watchdog removed" ;;
        --check) check ;;
        *) bad "Unknown option $1" ;;
    esac
    shift
done
