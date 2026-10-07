#!/usr/bin/env bash
# 14 - File checker: SUID/SGID, world-writable, and other permission problems
#   (no args)    Full report: SUID/SGID binaries (unexpected ones flagged), world-writable files &
#                dirs (dirs without sticky bit are worst), files with no owner, writable files in PATH,
#                writable systemd units / cron / sudoers, capabilities, and ~/.ssh perms
#   --suid       SUID/SGID only, comparing against a known-good baseline list
#   --baseline   Save the current SUID/SGID set as expected (do this after you trust the box)
#   --fix-ww     Remove world-writable bit from files (not dirs) outside /tmp,/var/tmp,/dev/shm (asks)
#   --fix-suid   Remove SUID bit from binaries NOT in the baseline/known-good list (asks, backs up list)
# Scans local filesystems only (skips nfs/proc/sys/containers overlay).
source "$(dirname "$0")/../lib.sh"
need_root
SDIR=$(outdir perms)
BASE="$SDIR/suid-baseline.txt"

# SUID binaries that are normal on a Linux box
KNOWN_SUID='/(sudo|su|mount|umount|passwd|chsh|chfn|gpasswd|newgrp|pkexec|fusermount[0-9]*|ping|ping6|crontab|at|ssh-keysign|dbus-daemon-launch-helper|polkit-agent-helper-1|unix_chkpwd|pam_extrausers_chkpwd|pam_timestamp_check|chage|expiry|write|wall|ntfs-3g|login|Xorg|snap-confine|utempter|mount.nfs|sg|umount.udisks2|vmware-user-suid-wrapper)$'

FS_PRUNE=( -fstype proc -o -fstype sysfs -o -fstype devtmpfs -o -fstype nfs -o -fstype nfs4 -o -fstype cifs -o -fstype overlay -o -fstype squashfs -o -path /proc -o -path /sys -o -path "$CF_OUT" )

find_local() { find / \( "${FS_PRUNE[@]}" \) -prune -o "$@" -print 2>/dev/null; }

report_suid() {
    info "== SUID / SGID binaries =="
    find_local -type f -perm /6000 | while read -r f; do
        p=$(stat -c '%A %U:%G' "$f")
        if [[ $f =~ $KNOWN_SUID ]]; then printf '  %-45s %s\n' "$f" "$p"
        else bad "  UNEXPECTED  $f  $p   (owner-writable shell? check it)"; fi
    done
}

report() {
    report_suid
    echo
    info "== Files with capabilities (getcap) =="
    have getcap && getcap -r / 2>/dev/null | grep -v "$CF_OUT" | sed 's/^/  /'

    echo; info "== World-writable DIRECTORIES without sticky bit (anyone can replace files here) =="
    find_local -type d -perm -0002 ! -perm -1000 | while read -r d; do bad "  $d"; done

    echo; info "== World-writable FILES (excluding /tmp /var/tmp /dev/shm /proc) =="
    find_local -type f -perm -0002 ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/dev/shm/*' | while read -r f; do
        warn "  $(stat -c '%A %U:%G %n' "$f")"
        # extra-bad: world-writable AND in a sensitive place
        [[ $f =~ /(etc|usr/bin|usr/sbin|bin|sbin|usr/local)/ ]] && bad "    ^ sensitive location!"
    done

    echo; info "== World-writable files in PATH directories (privesc) =="
    IFS=: read -ra P <<< "$PATH:/usr/local/sbin:/usr/sbin:/sbin"
    for d in "${P[@]}"; do [[ -d $d ]] && find "$d" -maxdepth 1 -perm -0002 2>/dev/null | while read -r f; do bad "  $f"; done; done

    echo; info "== Writable-by-nonroot systemd units / cron / sudoers (persistence) =="
    for d in /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/sudoers.d; do
        [[ -d $d ]] && find "$d" -perm /022 ! -user root 2>/dev/null | while read -r f; do bad "  $(stat -c '%A %U %n' "$f")"; done
        [[ -d $d ]] && find "$d" -perm -0002 2>/dev/null | while read -r f; do bad "  world-writable: $f"; done
    done

    echo; info "== Files/dirs with NO owner or NO group (deleted attacker account?) =="
    find_local \( -nouser -o -nogroup \) | head -40 | sed 's/^/  /'

    echo; info "== Home dirs / .ssh too open =="
    while IFS=: read -r u _ uid _ _ h _; do
        [[ $uid -ge 1000 || $u == root ]] || continue
        [[ -d $h ]] || continue
        perm=$(stat -c '%a' "$h")
        [[ ${perm:1} =~ [2367] ]] && warn "  $h is $perm (group/other writable)"
        if [[ -d $h/.ssh ]]; then
            sp=$(stat -c '%a' "$h/.ssh"); [[ $sp != 700 ]] && warn "  $h/.ssh is $sp (should be 700)"
            [[ -f $h/.ssh/authorized_keys ]] && { ap=$(stat -c '%a' "$h/.ssh/authorized_keys"); [[ $ap =~ [2367]$ || ${ap:1} =~ [2367] ]] && bad "  $h/.ssh/authorized_keys is $ap (too open)"; }
        fi
    done < /etc/passwd
    good "Scan done. Review anything in red."
}

baseline() { find_local -type f -perm /6000 | sort > "$BASE"; good "SUID/SGID baseline: $(wc -l < "$BASE") entries -> $BASE"; }

diff_suid() {
    [[ -f $BASE ]] || { bad "No baseline - run --baseline"; exit 1; }
    find_local -type f -perm /6000 | sort | comm -13 "$BASE" - | while read -r f; do bad "  NEW SUID/SGID since baseline: $f  $(stat -c '%U:%G' "$f")"; done
    good "(nothing above = no new SUID binaries)"
}

fix_ww() {
    mapfile -t files < <(find_local -type f -perm -0002 ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/dev/shm/*')
    [[ ${#files[@]} -eq 0 ]] && { good "No world-writable files to fix"; return; }
    printf '%s\n' "${files[@]}"
    confirm "Remove world-writable bit (o-w) from these ${#files[@]} files?" || return
    printf '%s\n' "${files[@]}" > "$SDIR/fixed-ww-$(stamp).txt"
    chmod o-w "${files[@]}" && good "Done (list saved in $SDIR)"
}

fix_suid() {
    [[ -f $BASE ]] || { bad "Run --baseline first so we know which SUID bins are legit"; exit 1; }
    mapfile -t extra < <(find_local -type f -perm /6000 | sort | comm -13 "$BASE" -)
    [[ ${#extra[@]} -eq 0 ]] && { good "No unexpected SUID binaries"; return; }
    printf '  %s\n' "${extra[@]}"
    confirm "Remove SUID/SGID bit from these ${#extra[@]} unexpected binaries?" || return
    printf '%s\n' "${extra[@]}" > "$SDIR/fixed-suid-$(stamp).txt"
    chmod u-s,g-s "${extra[@]}" && good "Stripped (restore with chmod u+s if it was legit; list in $SDIR)"
}

case ${1:-} in
    "")         report ;;
    --suid)     report_suid; echo; diff_suid ;;
    --baseline) baseline ;;
    --fix-ww)   fix_ww ;;
    --fix-suid) fix_suid ;;
    *) sed -n '2,11p' "$0" ;;
esac
