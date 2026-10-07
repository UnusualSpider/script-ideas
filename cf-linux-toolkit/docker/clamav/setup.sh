#!/usr/bin/env bash
# Run ClamAV from the official container and scan a host path (read-only mount).
#   setup.sh /var/www      scan that path
#   setup.sh /             scan the whole box (slow)
# The daemon container keeps signatures fresh; we exec clamdscan against the mount.
source "$(cd "$(dirname "$0")/.." && pwd)/common.sh"
need_root
ensure_docker
TARGET="${1:-/}"
RDIR="$(outdir reports)"; LOG="$RDIR/clamav-docker-$(stamp).log"

info "Starting clamav container (downloads signatures on first run)"
docker rm -f cf-clamav >/dev/null 2>&1 || true
docker run -d --name cf-clamav -v "$TARGET:/scan:ro" clamav/clamav:stable >/dev/null
info "Waiting for the signature database to load..."
for i in $(seq 1 30); do
    docker exec cf-clamav clamdscan --ping 1 >/dev/null 2>&1 && break
    sleep 10
done
info "Scanning $TARGET (reporting only, no deletion)"
docker exec cf-clamav clamdscan -i -m --fdpass /scan | tee "$LOG"
grep -c FOUND "$LOG" | xargs -I{} echo "Infected files: {}"
good "Report: $LOG   (stop container: docker rm -f cf-clamav)"
