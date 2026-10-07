#!/usr/bin/env bash
# Run Nikto and Wapiti web scanners from official/community containers (no local install).
#   scan.sh nikto  http://TARGET/
#   scan.sh wapiti http://TARGET/
#   scan.sh both   http://TARGET/
# Reports are written to $CF_OUT/reports/.
source "$(cd "$(dirname "$0")/.." && pwd)/common.sh"
ensure_docker
RDIR="$(outdir reports)"
TS=$(stamp)

run_nikto() {
    local url=$1 out="$RDIR/nikto-$TS.txt"
    info "Nikto -> $1"
    docker run --rm sullo/nikto -h "$url" -maxtime 300s | tee "$out"
    good "Saved $out"
}
run_wapiti() {
    local url=$1 out="$RDIR/wapiti-$TS"
    info "Wapiti -> $1"
    mkdir -p "$out"
    docker run --rm -v "$out:/output" cyberwatch/wapiti -u "$url" -f html -o /output 2>&1 | tail -20 || \
        warn "If that image is unavailable, try: docker run --rm -v $out:/output ghcr.io/wapiti-scanner/wapiti -u $url -o /output -f html"
    good "HTML report in $out"
}

case ${1:-} in
    nikto)  run_nikto "$2" ;;
    wapiti) run_wapiti "$2" ;;
    both)   run_nikto "$2"; run_wapiti "$2" ;;
    *) sed -n '2,6p' "$0" ;;
esac
