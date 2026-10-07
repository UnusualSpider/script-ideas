#!/usr/bin/env bash
# Helper for "dockerify" scored services.
#   --detect     Look at what this box runs (web/db/dns/ftp/mail) and tell you which compose
#                services apply, and where your real config/content lives to mount in.
#   --scaffold   Create ./web ./db ./dns ... directories next to docker-compose.yml and COPY
#                the box's current config/content into them (so the container serves the same thing).
#   --up  SVC... Stop the matching native service(s) and start the container(s)
#   --down SVC...
# This does NOT auto-migrate blindly - review the compose file and the copied config first.
source "$(cd "$(dirname "$0")/../.." && pwd)/lib.sh"
need_root
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

detect() {
    info "Detecting scored-service candidates on $(hostname):"
    declare -A map=(
        [apache2]=web [httpd]=web [nginx]=web
        [mysql]=db [mariadb]=db [mysqld]=db [postgresql]=db
        [named]=dns [bind9]=dns
        [vsftpd]=ftp [proftpd]=ftp [pure-ftpd]=ftp
        [postfix]=mail [dovecot]=mail
    )
    for svc in "${!map[@]}"; do
        if systemctl is-active -q "$svc" 2>/dev/null || have "$svc"; then
            printf '  %-12s -> compose service "%s"  (listening: %s)\n' "$svc" "${map[$svc]}" \
                "$(ss -tlnpH 2>/dev/null | grep -o "\"$svc\"" | head -1 || echo '-')"
        fi
    done
    echo
    info "Config/content to mount:"
    for p in /var/www /etc/apache2 /etc/httpd /etc/nginx /var/lib/mysql /var/lib/postgresql \
             /etc/bind /var/named /etc/vsftpd.conf /etc/postfix; do
        [[ -e $p ]] && echo "  $p"
    done
}

scaffold() {
    mkdir -p web/html web/conf db/data db/init dns/etc dns/zones ftp/data
    [[ -d /var/www/html ]] && { cp -a /var/www/html/. web/html/ 2>/dev/null; good "Copied /var/www/html -> web/html"; }
    for c in /etc/apache2/conf-enabled /etc/httpd/conf.d /etc/nginx/conf.d; do [[ -d $c ]] && cp -a "$c/." web/conf/ 2>/dev/null; done
    [[ -d /etc/bind ]] && cp -a /etc/bind/. dns/etc/ 2>/dev/null
    if have mysqldump && systemctl is-active -q mysql mariadb 2>/dev/null; then
        mysqldump --all-databases --single-transaction > db/init/dump.sql 2>/dev/null && good "DB dumped -> db/init/dump.sql (loads on container first start)"
    fi
    [[ -f db/root_password.txt ]] || { tr -dc A-Za-z0-9 </dev/urandom | head -c20 > db/root_password.txt; chmod 600 db/root_password.txt; good "Generated db/root_password.txt"; }
    good "Scaffold ready. Review docker-compose.yml, then: ./dockerize.sh --up web db"
}

native_of() { # compose svc -> native units to stop
    case $1 in
        web) echo "apache2 httpd nginx" ;; db) echo "mysql mariadb mysqld postgresql" ;;
        dns) echo "named bind9" ;; ftp) echo "vsftpd proftpd pure-ftpd" ;; mail) echo "postfix dovecot" ;;
    esac
}

up() {
    source "$HERE/../common.sh"; ensure_docker
    for s in "$@"; do for n in $(native_of "$s"); do systemctl is-active -q "$n" 2>/dev/null && { systemctl stop "$n"; systemctl disable "$n" 2>/dev/null; warn "Stopped native $n (frees the port)"; }; done; done
    $COMPOSE up -d "$@" && good "Containers up: $*"
    $COMPOSE ps
}
down() { source "$HERE/../common.sh"; ensure_docker; $COMPOSE down "$@"; }

case ${1:-} in
    --detect)   detect ;;
    --scaffold) scaffold ;;
    --up)       shift; up "$@" ;;
    --down)     shift; down "$@" ;;
    *) sed -n '2,10p' "$0" ;;
esac
