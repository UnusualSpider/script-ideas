#!/usr/bin/env bash
# 07 - Auto firewall (iptables / ip6tables, works on iptables-nft too)
#   (no args)    Preview: show listening ports and the rules that would be applied
#   --apply      Apply. A 60-second dead-man switch rolls back unless you type "yes" (keeps you from locking yourself out)
#   --auto       Also allow every port that is CURRENTLY listening on a non-loopback address
#   --egress     Also restrict OUTBOUND (allow DNS/HTTP/HTTPS/NTP + replies + mgmt only) - stops reverse shells, may break things
#   --rollback   Restore the rules saved before the last --apply
#   --status     Show current INPUT rules with counters
# Rules: default DROP inbound, allow loopback, established, ICMP echo, SSH only from CF_MGMT_SUBNETS,
# CF_ALLOWED_TCP/UDP from anywhere, CF_TRUSTED_IPS everything, log+drop the rest.
# Only the INPUT/OUTPUT chains are touched - Docker's FORWARD/NAT rules are left alone.
# Make it survive reboots with 15-firewall-persist.sh.
source "$(dirname "$0")/../lib.sh"
need_root
FDIR=$(outdir firewall)

AUTO=0; EGRESS=0; ACTION=preview
for a in "$@"; do case $a in
    --apply) ACTION=apply ;; --auto) AUTO=1 ;; --egress) EGRESS=1 ;;
    --rollback) ACTION=rollback ;; --status) ACTION=status ;; --yes) YES=1 ;;
    *) sed -n '2,13p' "$0"; exit 0 ;; esac; done

have iptables || { info "iptables missing - installing"; pkg_install iptables || exit 1; }

listening_ports() { # proto -> list of ports on non-loopback
    ss -H -ln"$1" 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|::1)' | sed -E 's/.*[:]([0-9]+)$/\1/' | sort -un
}

SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}'); SSH_PORT=${SSH_PORT:-22}
TCP=("${CF_ALLOWED_TCP[@]}"); UDP=("${CF_ALLOWED_UDP[@]}")
if [[ $AUTO -eq 1 ]]; then
    mapfile -t lt < <(listening_ports t); mapfile -t lu < <(listening_ports u)
    for p in "${lt[@]}"; do [[ $p == "$SSH_PORT" ]] || TCP+=("$p"); done
    for p in "${lu[@]}"; do [[ $p -ge 32768 ]] || UDP+=("$p"); done  # skip ephemeral client sockets
fi
mapfile -t TCP < <(printf '%s\n' "${TCP[@]}" | grep -v '^$' | sort -un)
mapfile -t UDP < <(printf '%s\n' "${UDP[@]}" | grep -v '^$' | sort -un)

show_plan() {
    info "Listening TCP (non-loopback): $(listening_ports t | xargs)"
    info "Listening UDP (non-loopback): $(listening_ports u | xargs)"
    echo
    echo "  INPUT policy DROP"
    echo "  allow  lo, ESTABLISHED/RELATED, ICMP echo"
    echo "  allow  SSH tcp/$SSH_PORT from: ${CF_MGMT_SUBNETS[*]} ${CF_TRUSTED_IPS[*]}"
    echo "  allow  TCP from anywhere: ${TCP[*]:-none}"
    echo "  allow  UDP from anywhere: ${UDP[*]:-none}"
    echo "  allow  ALL from trusted:  ${CF_TRUSTED_IPS[*]:-none}"
    [[ $EGRESS -eq 1 ]] && echo "  OUTPUT policy DROP - allow lo, established, DNS, HTTP/S, NTP, to mgmt/trusted"
    echo "  log + drop everything else (journalctl -k | grep CF-DROP)"
    for p in $(listening_ports t); do
        printf '%s\n' "${TCP[@]}" "$SSH_PORT" | grep -qx "$p" || warn "Port tcp/$p is listening but will be BLOCKED (use --auto or add to CF_ALLOWED_TCP)"
    done
}

fam_ok() { if [[ $v6 -eq 1 ]]; then [[ $1 == *:* ]]; else [[ $1 != *:* ]]; fi; }

build() { # $1 = iptables | ip6tables
    local ipt=$1 v6=0 s p
    [[ $ipt == ip6tables ]] && v6=1
    $ipt -N CF-IN 2>/dev/null; $ipt -F CF-IN
    $ipt -A CF-IN -i lo -j ACCEPT
    $ipt -A CF-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $ipt -A CF-IN -m conntrack --ctstate INVALID -j DROP
    if [[ $v6 -eq 0 ]]; then
        $ipt -A CF-IN -p icmp --icmp-type echo-request -m limit --limit 10/s -j ACCEPT
    else
        $ipt -A CF-IN -p ipv6-icmp -j ACCEPT    # v6 needs ND/RA
    fi
    for s in "${CF_TRUSTED_IPS[@]}"; do
        fam_ok "$s" && $ipt -A CF-IN -s "$s" -j ACCEPT
    done
    for s in "${CF_MGMT_SUBNETS[@]}"; do
        fam_ok "$s" && $ipt -A CF-IN -p tcp -s "$s" --dport "$SSH_PORT" -j ACCEPT
    done
    for p in "${TCP[@]}"; do $ipt -A CF-IN -p tcp --dport "$p" -j ACCEPT; done
    for p in "${UDP[@]}"; do $ipt -A CF-IN -p udp --dport "$p" -j ACCEPT; done
    $ipt -A CF-IN -m limit --limit 5/min -j LOG --log-prefix "CF-DROP: " --log-level 4
    $ipt -A CF-IN -j DROP
    # hook it in as the only INPUT rule
    $ipt -F INPUT
    $ipt -A INPUT -j CF-IN
    $ipt -P INPUT DROP

    if [[ $EGRESS -eq 1 ]]; then
        $ipt -N CF-OUT 2>/dev/null; $ipt -F CF-OUT
        $ipt -A CF-OUT -o lo -j ACCEPT
        $ipt -A CF-OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        $ipt -A CF-OUT -p udp --dport 53 -j ACCEPT;  $ipt -A CF-OUT -p tcp --dport 53 -j ACCEPT
        $ipt -A CF-OUT -p udp --dport 123 -j ACCEPT
        $ipt -A CF-OUT -p tcp -m multiport --dports 80,443 -j ACCEPT
        if [[ $v6 -eq 0 ]]; then $ipt -A CF-OUT -p icmp -j ACCEPT; else $ipt -A CF-OUT -p ipv6-icmp -j ACCEPT; fi
        for s in "${CF_MGMT_SUBNETS[@]}" "${CF_TRUSTED_IPS[@]}"; do
            fam_ok "$s" && $ipt -A CF-OUT -d "$s" -j ACCEPT
        done
        $ipt -A CF-OUT -m limit --limit 5/min -j LOG --log-prefix "CF-OUT-DROP: " --log-level 4
        $ipt -A CF-OUT -j DROP
        $ipt -F OUTPUT; $ipt -A OUTPUT -j CF-OUT; $ipt -P OUTPUT DROP
    fi
}

case $ACTION in
    status)   iptables -L INPUT -nv --line-numbers; iptables -L CF-IN -nv 2>/dev/null; exit 0 ;;
    rollback)
        f=$(ls -1t "$FDIR"/pre-apply-*.v4 2>/dev/null | head -1); [[ -n $f ]] || { bad "Nothing to roll back"; exit 1; }
        iptables-restore < "$f"; [[ -f ${f%.v4}.v6 ]] && ip6tables-restore < "${f%.v4}.v6"
        good "Rolled back to $(basename "$f")"; exit 0 ;;
    preview)  show_plan; echo; warn "Preview only. Re-run with --apply"; exit 0 ;;
esac

# --- apply ---
show_plan
if systemctl is-active -q firewalld 2>/dev/null; then warn "firewalld is running and will fight these rules - stopping it"; systemctl disable --now firewalld; fi
if have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then warn "ufw is active - disabling it (rules replaced by CF chains)"; ufw --force disable; fi

ts=$(stamp)
iptables-save > "$FDIR/pre-apply-$ts.v4"; have ip6tables-save && ip6tables-save > "$FDIR/pre-apply-$ts.v6"
build iptables
have ip6tables && build ip6tables 2>/dev/null
iptables-save > "$FDIR/current.v4"; have ip6tables-save && ip6tables-save > "$FDIR/current.v6"
good "Rules applied."

if [[ ${YES:-0} -ne 1 ]]; then
    warn "Open a NEW ssh session now to test. Type 'yes' within 60s to keep the rules, or they roll back."
    if read -r -t 60 ans && [[ $ans == yes ]]; then
        good "Rules kept. Make them persistent: tools/15-firewall-persist.sh --install"
    else
        iptables-restore < "$FDIR/pre-apply-$ts.v4"; [[ -f $FDIR/pre-apply-$ts.v6 ]] && ip6tables-restore < "$FDIR/pre-apply-$ts.v6"
        bad "No confirmation - ROLLED BACK to previous rules."
    fi
fi
