#!/usr/bin/env bash
# Deploy the Wazuh single-node SIEM stack (manager + indexer + dashboard) via Docker.
# Needs ~8 GB RAM and vm.max_map_count=262144. Dashboard is published on CF_WAZUH_DASH_PORT (default 8443)
# so it does not collide with a web server on 443.
source "$(cd "$(dirname "$0")/.." && pwd)/common.sh"
need_root
ensure_docker

WZ_VER="${WZ_VER:-v4.14.8}"          # pinned; bump if a newer tag is out
APP=/opt/cf-wazuh

info "Setting vm.max_map_count=262144 (required by the indexer)"
sysctl -w vm.max_map_count=262144 >/dev/null
grep -q '^vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf

if [[ ! -d $APP/wazuh-docker ]]; then
    mkdir -p "$APP"
    info "Cloning wazuh-docker $WZ_VER"
    git clone -q https://github.com/wazuh/wazuh-docker.git -b "$WZ_VER" "$APP/wazuh-docker"
fi
cd "$APP/wazuh-docker/single-node"

# Publish the dashboard on a non-conflicting host port
if [[ "${CF_WAZUH_DASH_PORT:-8443}" != "443" ]]; then
    sed -i -E "s|- \"?443:5601\"?|- \"${CF_WAZUH_DASH_PORT:-8443}:5601\"|" docker-compose.yml || true
fi

info "Generating certificates (one-time)"
$COMPOSE -f generate-indexer-certs.yml run --rm generator

info "Starting the stack (first start pulls images and can take several minutes)"
$COMPOSE up -d

cat <<EOF

$(good "Wazuh is starting.")
  Dashboard : https://<this-host>:${CF_WAZUH_DASH_PORT:-8443}
  Login     : admin / SecretPassword   (DEFAULT - change it immediately)
  Change pw : see $APP/wazuh-docker/single-node/README and the Wazuh docs
              (edit internal_users + wazuh.yml, or use the indexer security tool)
  Logs      : cd $APP/wazuh-docker/single-node && $COMPOSE logs -f
  Stop      : $COMPOSE down         Wipe: $COMPOSE down -v

Next: on every other Linux box run   tools/09-siem-wazuh.sh --agent <this-host-ip>
      for Windows, download the agent from the dashboard (Agents > Deploy new agent).
EOF
warn "CHANGE the default admin password before the attack phase - it is public knowledge."
