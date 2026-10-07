#!/usr/bin/env bash
# 02 - Security tool installer: Lynis, OpenVAS (Greenbone), Nikto, Wapiti, otseca
# Usage:
#   02-install-tools.sh --all
#   02-install-tools.sh --lynis --nikto --wapiti --otseca
#   02-install-tools.sh --openvas            # Docker (recommended) - see docker/openvas
#   02-install-tools.sh --openvas-native     # distro 'gvm' package (Kali/Ubuntu/Debian)
#   02-install-tools.sh --run-lynis | --run-otseca   # install if needed, then audit this box
# Everything is installed under /opt/cf-tools and recorded in $CF_OUT/installed-tools.txt
# so 08-tool-remover.sh --ours can remove it again.
source "$(dirname "$0")/../lib.sh"
need_root

TOOLS_DIR=/opt/cf-tools
MANIFEST="$CF_OUT/installed-tools.txt"
mkdir -p "$TOOLS_DIR"
record() { grep -qxF "$1" "$MANIFEST" 2>/dev/null || echo "$1" >> "$MANIFEST"; }

ensure_base() {
    pkg_update >/dev/null 2>&1
    for p in git curl perl; do have "$p" || pkg_install "$p"; done
}

install_lynis() {
    info "Installing Lynis"
    if [[ -d $TOOLS_DIR/lynis/.git ]]; then git -C "$TOOLS_DIR/lynis" pull -q
    else git clone -q --depth 1 https://github.com/CISOfy/lynis "$TOOLS_DIR/lynis"; fi
    ln -sf "$TOOLS_DIR/lynis/lynis" /usr/local/bin/lynis
    record "dir:$TOOLS_DIR/lynis"; record "link:/usr/local/bin/lynis"
    good "Lynis ready: lynis audit system   (run from $TOOLS_DIR/lynis)"
}

install_nikto() {
    info "Installing Nikto"
    for p in libnet-ssleay-perl libjson-perl perl-Net-SSLeay perl-JSON; do pkg_install "$p" >/dev/null 2>&1 || true; done
    if [[ -d $TOOLS_DIR/nikto/.git ]]; then git -C "$TOOLS_DIR/nikto" pull -q
    else git clone -q --depth 1 https://github.com/sullo/nikto "$TOOLS_DIR/nikto"; fi
    cat > /usr/local/bin/nikto <<EOF
#!/bin/sh
cd $TOOLS_DIR/nikto/program && exec perl ./nikto.pl "\$@"
EOF
    chmod +x /usr/local/bin/nikto
    record "dir:$TOOLS_DIR/nikto"; record "link:/usr/local/bin/nikto"
    good "Nikto ready: nikto -h http://<target>"
}

install_wapiti() {
    info "Installing Wapiti (Python venv)"
    detect_pm
    case $PM in
        apt) pkg_install python3-venv python3-pip >/dev/null ;;
        dnf|yum) pkg_install python3 python3-pip >/dev/null ;;
        *) pkg_install python3 >/dev/null ;;
    esac
    python3 -m venv "$TOOLS_DIR/wapiti-venv" || { bad "python3 venv failed"; return 1; }
    "$TOOLS_DIR/wapiti-venv/bin/pip" install -q --upgrade pip
    "$TOOLS_DIR/wapiti-venv/bin/pip" install -q wapiti3 || { bad "pip install wapiti3 failed (needs Python 3.10+). Use docker/scanners instead."; return 1; }
    ln -sf "$TOOLS_DIR/wapiti-venv/bin/wapiti" /usr/local/bin/wapiti
    record "dir:$TOOLS_DIR/wapiti-venv"; record "link:/usr/local/bin/wapiti"
    good "Wapiti ready: wapiti -u http://<target>/ -o /opt/cf/reports/wapiti"
}

install_otseca() {
    info "Installing otseca"
    if [[ -d $TOOLS_DIR/otseca/.git ]]; then git -C "$TOOLS_DIR/otseca" pull -q
    else git clone -q --depth 1 https://github.com/trimstray/otseca "$TOOLS_DIR/otseca"; fi
    (cd "$TOOLS_DIR/otseca" && ./setup.sh install) >/dev/null
    record "dir:$TOOLS_DIR/otseca"; record "link:/usr/local/bin/otseca"
    good "otseca ready: otseca --ignore-failed --output $CF_OUT/reports/otseca"
}

install_openvas_docker() {
    info "OpenVAS/Greenbone via Docker"
    bash "$CF_ROOT/docker/openvas/setup.sh"
}

install_openvas_native() {
    info "OpenVAS/Greenbone via distro packages (large download, feed sync takes a LONG time)"
    detect_pm
    [[ $PM == apt ]] || { bad "Native install only scripted for Debian/Ubuntu/Kali. Use --openvas (Docker)."; return 1; }
    pkg_install gvm || { bad "'gvm' package not available here. Use --openvas (Docker)."; return 1; }
    gvm-setup | tee "$CF_OUT/reports/gvm-setup.log"
    gvm-check-setup
    record "pkg:gvm"
    warn "Admin password is printed in $CF_OUT/reports/gvm-setup.log - change it: gvmd --user=admin --new-password=..."
}

run_lynis() {
    have lynis || install_lynis
    local r; r="$(outdir reports)/lynis-$(hostname)-$(stamp)"
    (cd "$TOOLS_DIR/lynis" && ./lynis audit system --quick --no-colors --logfile "$r.log" --report-file "$r.dat") | tee "$r.txt"
    echo; info "Top findings:"; grep -E '^(warning|suggestion)\[\]=' "$r.dat" | head -40
    good "Lynis report: $r.txt  (hardening index: $(grep hardening_index "$r.dat" | cut -d= -f2))"
}

run_otseca() {
    have otseca || install_otseca
    local r; r="$(outdir reports)/otseca-$(stamp)"
    otseca --ignore-failed --tasks system,kernel,permissions,services,network,distro --output "$r"
    good "otseca HTML report in $r"
}

[[ $# -eq 0 ]] && { sed -n '2,11p' "$0"; exit 0; }
ensure_base
for a in "$@"; do
    case $a in
        --all)            install_lynis; install_nikto; install_wapiti; install_otseca; install_openvas_docker ;;
        --lynis)          install_lynis ;;
        --nikto)          install_nikto ;;
        --wapiti)         install_wapiti ;;
        --otseca)         install_otseca ;;
        --openvas)        install_openvas_docker ;;
        --openvas-native) install_openvas_native ;;
        --run-lynis)      run_lynis ;;
        --run-otseca)     run_otseca ;;
        *) bad "Unknown option $a" ;;
    esac
done
