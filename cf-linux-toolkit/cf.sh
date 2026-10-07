#!/usr/bin/env bash
# CyberForce Linux Toolkit - menu launcher
#   sudo ./cf.sh            interactive menu
#   sudo ./cf.sh 1          run tool 1 directly (passes the rest of the args through)
#   sudo ./cf.sh harden-all run the recommended setup-phase sequence
source "$(dirname "$0")/lib.sh"
need_root
T="$CF_ROOT/tools"

run() { bash "$T/$1" "${@:2}"; }

harden_all() {
    warn "This runs the SAFE setup-phase sequence (snapshots + read-only scans + previews)."
    warn "It does NOT apply firewall/ssh/user enforcement - you do that after reviewing output."
    confirm "Continue?" || return
    run 01-machine-info.sh
    run 04-backup.sh
    run 05-user-snapshot.sh --snapshot
    run 03-ssh-guard.sh --snapshot
    run 10-file-monitor.sh --baseline
    run 11-process-monitor.sh --baseline
    run 13-tcp-monitor.sh --baseline
    run 14-suid-worldwritable.sh --baseline
    run 06-cron-nuke.sh                 # list only
    run 07-firewall.sh                  # preview only
    good "Setup snapshots + baselines done. Now review, edit config.sh, and apply:"
    cat <<EOF
  1) tools/03-ssh-guard.sh --harden --add-key team.pub   (keep your access)
  2) tools/06-cron-nuke.sh --nuke                         (kill rogue cron)
  3) tools/07-firewall.sh --apply                         (lock down inbound)
  4) tools/15-firewall-persist.sh --install --watchdog    (make it stick)
  5) tools/05-user-snapshot.sh --watchdog-install --enforce
  6) tools/10-file-monitor.sh --watch-install  &&  --auditd
  7) tools/12-malware-scanner.sh --install --update --scan
EOF
}

menu() {
    while true; do
        clear
        cat <<EOF
${C_CYAN}===================================================================
  CyberForce Linux Blue-Team Toolkit     host: $(hostname)
  output: $CF_OUT        config: $CF_ROOT/config.sh
===================================================================${C_RESET}
  ${C_YEL}S) SETUP PHASE - snapshots, baselines, previews (safe)${C_RESET}
   1) Machine & service info
   2) Install security tools (Lynis/OpenVAS/Nikto/Wapiti/otseca)
   3) SSH guard (harden / keys / watchdog)
   4) Tarball backup
   5) User/group snapshot + drift guard
   6) Cron nuke (list / nuke rogue jobs)
   7) Auto firewall (preview / apply)
   9) SIEM - Wazuh (manager / agent)
  10) File integrity monitor (baseline / scan / watch / auditd)
  11) Process monitor
  12) Malware/rootkit scanner (ClamAV/rkhunter/chkrootkit)
  13) TCP session monitor
  14) SUID / world-writable checker
  15) Persist firewall across reboots + watchdog
   D) Dockerize scored services (detect / scaffold / up)
   C) Edit config.sh          Q) Quit
EOF
        read -r -p "choose> " c
        case ${c^^} in
            S) harden_all ;;
            1) run 01-machine-info.sh ;;
            2) echo "flags: --all --lynis --nikto --wapiti --otseca --openvas --run-lynis --run-otseca"; read -r -p "args> " a; run 02-install-tools.sh $a ;;
            3) echo "flags: --harden [--restrict-users] --add-key F --audit-keys --purge-keys --snapshot --watchdog-install"; read -r -p "args> " a; run 03-ssh-guard.sh $a ;;
            4) echo "flags: (blank)=backup --encrypt --export u@h:/dir --list --restore TAR [paths] --restore-db TAR"; read -r -p "args> " a; run 04-backup.sh $a ;;
            5) echo "flags: --snapshot --diff --restore --watchdog-install [--enforce] --watchdog-remove"; read -r -p "args> " a; run 05-user-snapshot.sh $a ;;
            6) echo "flags: (blank)=list --nuke --lock --restore DIR"; read -r -p "args> " a; run 06-cron-nuke.sh $a ;;
            7) echo "flags: (blank)=preview --apply [--auto] [--egress] --rollback --status"; read -r -p "args> " a; run 07-firewall.sh $a ;;
            9) echo "flags: --manager --agent [IP] --status --remove-agent"; read -r -p "args> " a; run 09-siem-wazuh.sh $a ;;
            10) echo "flags: --baseline --scan --watch --watch-install --auditd"; read -r -p "args> " a; run 10-file-monitor.sh $a ;;
            11) echo "flags: (blank)=scan --baseline --watch [SEC] --tree"; read -r -p "args> " a; run 11-process-monitor.sh $a ;;
            12) echo "flags: --install --update --scan [DIR] --quick --docker [DIR]"; read -r -p "args> " a; run 12-malware-scanner.sh $a ;;
            13) echo "flags: (blank)=snapshot --watch [SEC] --established --outbound --baseline --diff --kill IP"; read -r -p "args> " a; run 13-tcp-monitor.sh $a ;;
            14) echo "flags: (blank)=report --suid --baseline --fix-ww --fix-suid"; read -r -p "args> " a; run 14-suid-worldwritable.sh $a ;;
            15) echo "flags: --install --save --watchdog --watchdog-remove --remove"; read -r -p "args> " a; run 15-firewall-persist.sh $a ;;
            D) echo "flags: --detect --scaffold --up SVC... --down SVC..."; read -r -p "args> " a; bash "$CF_ROOT/docker/services/dockerize.sh" $a ;;
            C) "${EDITOR:-vi}" "$CF_ROOT/config.sh"; source "$CF_ROOT/config.sh" ;;
            Q) exit 0 ;;
        esac
        read -r -p "press Enter..." _
    done
}

case ${1:-} in
    "")          menu ;;
    harden-all|S|s) harden_all ;;
    [0-9]*)      f=$(ls "$T" | grep -E "^0*$1-") ; [[ -n $f ]] && run "$f" "${@:2}" || bad "No tool $1" ;;
    *) bad "Unknown: $1"; sed -n '2,5p' "$0" ;;
esac
