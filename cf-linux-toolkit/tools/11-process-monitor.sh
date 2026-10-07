#!/usr/bin/env bash
# 11 - Process monitor
#   (no args)         One-shot: suspicious processes (reverse shells, miners, deleted binaries,
#                     execs from tmp, high CPU, orphaned listeners) + scored-service check
#   --baseline        Record the current set of process names as "normal"
#   --watch [SEC]     Loop every SEC seconds (default 10), print only NEW/suspicious since last tick
#   --tree            Full annotated process tree
# Read-only unless you choose to kill something (it will ask).
source "$(dirname "$0")/../lib.sh"
need_root
PDIR=$(outdir procmon)
BASE="$PDIR/proc-baseline.txt"

SUS='(nc |ncat|netcat|socat|/dev/tcp|/dev/udp|bash -i|sh -i|/tmp/|/dev/shm|/var/tmp/|xmrig|minerd|kinsing|kdevtmpfsi|\.\/|perl -e.*(socket|accept)|python[0-9.]* -c.*(socket|pty)|base64 -d|wget .*http|curl .*http|masscan|nmap)'

suspicious_scan() {
    info "== Processes running from world-writable / temp dirs =="
    ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '/(tmp|var/tmp|dev/shm)/' | sed 's/^/  /'

    info "== Processes whose binary was deleted (classic in-memory malware) =="
    for e in /proc/[0-9]*/exe; do
        t=$(readlink "$e" 2>/dev/null) || continue
        [[ $t == *"(deleted)"* ]] && { pid=$(echo "$e" | grep -oE '[0-9]+'); bad "  PID $pid ($(cat /proc/"$pid"/comm 2>/dev/null)) -> $t  cmd: $(tr '\0' ' ' </proc/"$pid"/cmdline 2>/dev/null)"; }
    done

    info "== Suspicious command lines =="
    ps -eo pid,user,etime,pcpu,args --no-headers | grep -iE "$SUS" | grep -vE 'grep -|11-process-monitor|inotifywait' | while read -r l; do bad "  $l"; done

    info "== Unexpected listeners (port -> process) not in CF_ALLOWED_TCP/scored =="
    ss -H -tlnp 2>/dev/null | while read -r line; do
        port=$(echo "$line" | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/')
        proc=$(echo "$line" | grep -oE 'users:\(\("[^"]+"' | sed -E 's/.*"(.*)"/\1/')
        printf '%s\n' "${CF_ALLOWED_TCP[@]}" 22 | grep -qx "$port" || warn "  tcp/$port  $proc"
    done

    info "== Top CPU =="
    ps -eo pid,user,pcpu,pmem,etime,comm --sort=-pcpu --no-headers | head -5 | sed 's/^/  /'

    info "== Scored services =="
    for s in "${CF_SCORED_SERVICES[@]}"; do
        if systemctl is-active -q "$s"; then good "  $s up"; else bad "  $s DOWN"; fi
    done

    # processes with no matching package / unusual parent (PPID 1 shells)
    info "== Shells / interpreters reparented to init (possible daemonized shell) =="
    ps -eo pid,ppid,user,comm --no-headers | awk '$2==1 && $4 ~ /^(bash|sh|dash|zsh|nc|ncat|socat|python|perl)$/ {print "  "$0}'
}

baseline() {
    ps -eo comm --no-headers | sort -u > "$BASE"
    good "Process baseline: $(wc -l < "$BASE") distinct names"
}

watch() {
    local sec=${1:-10}
    [[ -f $BASE ]] || baseline
    info "Watching every ${sec}s. Ctrl+C to stop. New process names and suspicious cmdlines only."
    local seen; seen=$(mktemp); cp "$BASE" "$seen"
    while true; do
        ps -eo comm --no-headers | sort -u | comm -13 "$seen" - | while read -r c; do
            warn "$(date +%H:%M:%S) NEW process: $c  ->  $(pgrep -x "$c" | head -1 | xargs -I{} sh -c 'tr "\0" " " </proc/{}/cmdline' 2>/dev/null)"
        done
        ps -eo comm --no-headers | sort -u > "$seen"
        ps -eo pid,etime,args --no-headers | grep -iE "$SUS" | grep -vE 'grep -|process-monitor|inotifywait' | while read -r l; do bad "$(date +%H:%M:%S) SUSPICIOUS: $l"; done
        sleep "$sec"
    done
}

case ${1:-} in
    "")        suspicious_scan ;;
    --baseline) baseline ;;
    --watch)   watch "${2:-10}" ;;
    --tree)    ps -eo pid,ppid,user,etime,pcpu,args --forest ;;
    *) sed -n '2,9p' "$0" ;;
esac
