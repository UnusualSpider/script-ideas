#!/usr/bin/env bash
# Shared helpers for the docker/ setup scripts
set -euo pipefail
DOCK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$DOCK_DIR/../lib.sh"

ensure_docker() {
    if ! have docker; then
        info "Installing Docker Engine"
        if have curl; then curl -fsSL https://get.docker.com | sh
        else pkg_install docker.io || pkg_install docker; fi
    fi
    systemctl enable --now docker 2>/dev/null || true
    # compose v2 plugin or standalone?
    if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
    elif have docker-compose; then COMPOSE="docker-compose"
    else
        detect_pm
        [[ $PM == apt ]] && pkg_install docker-compose-plugin >/dev/null 2>&1 || true
        docker compose version >/dev/null 2>&1 && COMPOSE="docker compose" || { bad "No docker compose available"; exit 1; }
    fi
    export COMPOSE
    good "Docker ready ($COMPOSE)"
}
