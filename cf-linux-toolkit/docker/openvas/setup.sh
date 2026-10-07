#!/usr/bin/env bash
# Deploy OpenVAS / Greenbone Community Edition via the official container compose file.
# The vulnerability feed sync on first run is large and can take 15-60+ minutes.
# Web UI (GSA) ends up on https://127.0.0.1:9392 by default; we also expose it on 0.0.0.0:9392
# so your team can reach it. admin password is set below.
source "$(cd "$(dirname "$0")/.." && pwd)/common.sh"
need_root
ensure_docker

APP=/opt/cf-openvas
mkdir -p "$APP"; cd "$APP"
COMPOSE_URL="https://greenbone.github.io/docs/latest/_static/compose.yaml"

if [[ ! -f compose.yaml ]]; then
    info "Downloading Greenbone compose file"
    curl -fsSL -o compose.yaml "$COMPOSE_URL" || { bad "Download failed (proxy?). Grab $COMPOSE_URL manually into $APP"; exit 1; }
    # expose GSA on all interfaces for the team (default binds 127.0.0.1 only)
    sed -i -E 's|127\.0\.0\.1:9392:9392|9392:9392|' compose.yaml || true
fi

info "Pulling images"
$COMPOSE -f compose.yaml -p greenbone-community-edition pull
info "Starting Greenbone (feed sync runs in the background and takes a long time)"
$COMPOSE -f compose.yaml -p greenbone-community-edition up -d

ADMIN_PW="${OPENVAS_ADMIN_PW:-CyberForce!$(tr -dc A-Za-z0-9 </dev/urandom | head -c8)}"
info "Waiting for gvmd to come up to set the admin password..."
for i in $(seq 1 30); do
    if $COMPOSE -f compose.yaml -p greenbone-community-edition exec -u gvmd -T gvmd gvmd --get-users >/dev/null 2>&1; then
        $COMPOSE -f compose.yaml -p greenbone-community-edition exec -u gvmd -T gvmd gvmd --user=admin --new-password="$ADMIN_PW" && break
    fi
    sleep 10
done

cat <<EOF

$(good "Greenbone/OpenVAS deployed.")
  Web UI    : https://<this-host>:9392
  Login     : admin / $ADMIN_PW
  (saved to $APP/admin-password.txt)
  Feed sync : still downloading - scans won't be complete until it finishes.
              Watch: $COMPOSE -f $APP/compose.yaml -p greenbone-community-edition logs -f
  Stop      : cd $APP && $COMPOSE -p greenbone-community-edition down
EOF
echo "admin / $ADMIN_PW" > "$APP/admin-password.txt"; chmod 600 "$APP/admin-password.txt"
