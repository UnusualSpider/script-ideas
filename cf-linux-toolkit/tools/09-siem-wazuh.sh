#!/usr/bin/env bash
# 09 - Auto SIEM setup (Wazuh)
#   --manager            Run the Wazuh manager + indexer + dashboard on THIS box via Docker (needs ~8 GB RAM)
#   --agent [MANAGER_IP] Install the Wazuh agent here and point it at the manager (default: CF_WAZUH_MANAGER)
#   --status             Agent / manager status
#   --remove-agent       Uninstall the agent
# Put the manager on your strongest box, then run --agent on every other Linux machine.
# Windows machines: install the agent MSI from the dashboard (Agents > Deploy new agent).
source "$(dirname "$0")/../lib.sh"
need_root
WAZUH_MAJOR=4.x

install_agent() {
    local mgr=${1:-$CF_WAZUH_MANAGER}
    [[ -n $mgr ]] || { bad "Give the manager IP: $0 --agent 10.0.0.5  (or set CF_WAZUH_MANAGER)"; exit 1; }
    detect_pm
    case $PM in
        apt)
            pkg_install gnupg apt-transport-https curl >/dev/null
            curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/$WAZUH_MAJOR/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
            apt-get update -y >/dev/null
            WAZUH_MANAGER="$mgr" WAZUH_AGENT_NAME="$(hostname)" DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent ;;
        dnf|yum|zypper)
            rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
            cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/$WAZUH_MAJOR/yum/
protect=1
EOF
            [[ $PM == zypper ]] && cp /etc/yum.repos.d/wazuh.repo /etc/zypp/repos.d/ 2>/dev/null
            WAZUH_MANAGER="$mgr" WAZUH_AGENT_NAME="$(hostname)" pkg_install wazuh-agent ;;
        *) bad "Unsupported distro for scripted agent install"; exit 1 ;;
    esac

    local conf=/var/ossec/etc/ossec.conf
    [[ -f $conf ]] || { bad "Agent install failed"; exit 1; }
    # Make sure the manager address is set even if the env var was ignored
    sed -i "s|<address>.*</address>|<address>$mgr</address>|" "$conf"

    # Extra file-integrity monitoring on the places attackers drop things (realtime)
    if ! grep -q 'CF-FIM' "$conf"; then
        sed -i '0,/<syscheck>/s|<syscheck>|<syscheck>\n    <!-- CF-FIM -->\n    <directories realtime="yes" check_all="yes">/etc,/usr/local/bin,/root/.ssh</directories>\n    <directories realtime="yes" check_all="yes">/tmp,/var/tmp,/dev/shm</directories>\n    <directories realtime="yes" check_all="yes" report_changes="yes">/var/www</directories>\n    <frequency>300</frequency>|' "$conf"
    fi
    systemctl daemon-reload
    systemctl enable --now wazuh-agent
    sleep 3
    systemctl is-active -q wazuh-agent && good "Wazuh agent running -> manager $mgr (check Agents in the dashboard)" || bad "Agent not running: journalctl -u wazuh-agent"
    # Stop the agent being auto-upgraded mid-competition
    have apt-mark && apt-mark hold wazuh-agent >/dev/null 2>&1
}

case ${1:-} in
    --manager)      bash "$CF_ROOT/docker/wazuh/setup.sh" ;;
    --agent)        install_agent "${2:-}" ;;
    --status)
        systemctl status wazuh-agent --no-pager 2>/dev/null | head -5
        [[ -f /var/ossec/var/run/wazuh-agentd.state ]] && grep -E '^(status|last_ack)' /var/ossec/var/run/wazuh-agentd.state
        have docker && docker ps --filter name=single-node --format 'table {{.Names}}\t{{.Status}}' ;;
    --remove-agent) systemctl disable --now wazuh-agent; pkg_remove wazuh-agent; good "Agent removed" ;;
    *) sed -n '2,8p' "$0" ;;
esac
