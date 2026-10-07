#!/usr/bin/env bash
# 13 - TCP monitor: active TCP sessions
#   (no args)        Snapshot: listeners + established connections (local/remote/process), grouped
#   --watch [SEC]    Refresh every SEC seconds (default 3), highlight NEW connections since last tick
#   --established    Only established sessions, with the owning process and user
#   --outbound       Only OUTBOUND established sessions (a reverse shell shows up here)
#   --baseline       Record current established remote IPs as expected
#   --diff           Established remote IPs not in the baseline (new talkers)
#   --kill IP        Kill every process that has a connection to IP (asks first)
# Flags connections to/from non-management, non-scored remote hosts.
source "$(dirname "$0")/../lib.sh"
need_root
TDIR=$(outdir tcpmon)
BASE="$TDIR/remote-baseline.txt"

in_known() { # ip - is it loopback / mgmt / trusted?
    local ip=$1
    [[ $ip =~ ^(127\.|::1|0\.0\.0\.0|\*) ]] && return 0
    local s
    for s in "${CF_TRUSTED_IPS[@]}" "${CF_MGMT_SUBNETS[@]}"; do [[ $ip == "${s%/*}"* ]] && return 0; done
    return 1
}

snapshot() {
    info "== Listening sockets =="
    ss -tlnpH | awk '{print $4"\t"$6}' | sort -V | sed 's/^/  /'
    echo
    info "== Established sessions (local -> remote  user/process) =="
    ss -tnpH state established | while read -r line; do
        local_a=$(echo "$line" | awk '{print $3}')
        rem=$(echo "$line" | awk '{print $4}')
        proc=$(echo "$line" | grep -oE 'users:\(.*' )
        rip=${rem%:*}
        if in_known "$rip"; then printf '  %-22s -> %-22s %s\n' "$local_a" "$rem" "$proc"
        else bad "  $local_a -> $rem  $proc  [external]"; fi
    done
    echo
    info "Connection count by remote IP:"
    ss -tnH state established | awk '{print $4}' | sed -E 's/:[0-9]+$//' | sort | uniq -c | sort -rn | head | sed 's/^/  /'
}

established() { ss -tnp state established 2>/dev/null; }

outbound() {
    info "Outbound established (watch for shells calling home):"
    # outbound = local port is ephemeral / remote port is well-known or local port not a listener
    local listeners; listeners=$(ss -tlnH | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -u | tr '\n' '|')
    ss -tnpH state established | while read -r line; do
        lport=$(echo "$line" | awk '{print $3}' | sed -E 's/.*:([0-9]+)$/\1/')
        rem=$(echo "$line" | awk '{print $4}'); proc=$(echo "$line" | grep -oE 'users:\(.*')
        echo "|$listeners|" | grep -q "|$lport|" && continue   # this is an inbound conn to our listener
        rip=${rem%:*}
        if in_known "$rip"; then printf '  -> %-22s %s\n' "$rem" "$proc"; else bad "  -> $rem  $proc  [EXTERNAL - investigate]"; fi
    done
}

watch() {
    local sec=${1:-3} prev; prev=$(mktemp)
    trap 'rm -f "$prev"; exit 0' INT
    while true; do
        clear; echo "=== TCP monitor $(date +%H:%M:%S) (every ${sec}s, Ctrl+C to quit) ==="
        cur=$(ss -tnH state established | awk '{print $3" -> "$4}' | sort)
        echo "$cur" | comm -13 "$prev" - 2>/dev/null | sed 's/^/NEW  /'
        echo "$cur" > "$prev"
        echo "--- all established ---"; ss -tnpH state established | awk '{print $3" -> "$4"  "$6}' | sort | head -40
        sleep "$sec"
    done
}

baseline() { ss -tnH state established | awk '{print $4}' | sed -E 's/:[0-9]+$//' | sort -u > "$BASE"; good "Baselined $(wc -l < "$BASE") remote IPs"; }
diff_ips() {
    [[ -f $BASE ]] || { bad "No baseline"; exit 1; }
    ss -tnH state established | awk '{print $4}' | sed -E 's/:[0-9]+$//' | sort -u | comm -13 "$BASE" - |
        while read -r ip; do in_known "$ip" && echo "  (known) $ip" || bad "  NEW remote: $ip"; done
}
kill_ip() {
    local ip=$1 pids
    pids=$(ss -tnpH | grep "$ip" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
    [[ -n $pids ]] || { warn "No connections to $ip"; exit 0; }
    echo "PIDs talking to $ip: $pids"; ps -p "$(echo "$pids" | tr '\n' ,)" -o pid,user,args 2>/dev/null
    confirm "Kill these?" && { kill -9 $pids && good "Killed"; }
}

case ${1:-} in
    "")            snapshot ;;
    --watch)       watch "${2:-3}" ;;
    --established) established ;;
    --outbound)    outbound ;;
    --baseline)    baseline ;;
    --diff)        diff_ips ;;
    --kill)        kill_ip "$2" ;;
    *) sed -n '2,11p' "$0" ;;
esac
