#!/usr/bin/env bash
# 04 - Tarball backup exporter
#   (no args)                 Back up configs, web roots, home dirs, cron, DB dumps -> $CF_OUT/backup/*.tar.gz
#   --encrypt                 Also produce an AES-256 encrypted copy (.tar.gz.enc, prompts for passphrase)
#   --export user@host:/dir   Copy the newest backup off-box with scp (do this! backups on the box can be wiped)
#   --list                    List backups
#   --restore TAR [PATH...]   Restore whole backup, or only the given paths (e.g. etc/nginx var/www)
#   --restore-db TAR          Re-import the MySQL / PostgreSQL dumps from a backup
source "$(dirname "$0")/../lib.sh"
need_root
BDIR=$(outdir backup)

DEFAULT_PATHS=(/etc /var/www /srv /home /root /var/spool/cron /var/spool/cron/crontabs /usr/local/bin /usr/local/sbin /opt
               /var/lib/bind /var/named /var/ftp /var/mail "${CF_BACKUP_EXTRA[@]}")

do_backup() {
    local ts work tarf paths=() p
    ts=$(stamp); work=$(mktemp -d); tarf="$BDIR/$(hostname)-$ts.tar.gz"
    for p in "${DEFAULT_PATHS[@]}"; do [[ -e $p ]] && paths+=("${p#/}"); done

    # Database dumps
    mkdir -p "$work/db"
    if have mysqldump && systemctl is-active -q mysql mariadb mysqld 2>/dev/null; then
        if mysqldump --all-databases --single-transaction --routines --events > "$work/db/mysql-all.sql" 2>"$work/db/mysql.err"; then
            good "MySQL dump: $(du -h "$work/db/mysql-all.sql" | cut -f1)"
        else warn "mysqldump failed (needs root socket auth or ~/.my.cnf): $(head -1 "$work/db/mysql.err")"; fi
    fi
    if have pg_dumpall && systemctl is-active -q postgresql 2>/dev/null; then
        if su - postgres -c pg_dumpall > "$work/db/postgres-all.sql" 2>"$work/db/pg.err"; then
            good "PostgreSQL dump: $(du -h "$work/db/postgres-all.sql" | cut -f1)"
        else warn "pg_dumpall failed: $(head -1 "$work/db/pg.err")"; fi
    fi
    # Package list & firewall rules (handy for rebuilding)
    (dpkg -l 2>/dev/null || rpm -qa 2>/dev/null) > "$work/packages.txt"
    iptables-save > "$work/iptables.rules" 2>/dev/null
    have nft && nft list ruleset > "$work/nftables.rules" 2>/dev/null
    crontab -l > "$work/root-crontab" 2>/dev/null

    info "Archiving: ${paths[*]}"
    tar --exclude="${CF_OUT#/}" --exclude='opt/cf-tools' --exclude='*/node_modules' --exclude='home/*/.cache' \
        --exclude='var/www/*/cache' --ignore-failed-read --warning=no-file-changed -czpf "$tarf" \
        -C / "${paths[@]}" -C "$work" db packages.txt iptables.rules $( [[ -f $work/nftables.rules ]] && echo nftables.rules ) $( [[ -s $work/root-crontab ]] && echo root-crontab ) 2>"$BDIR/tar-$ts.err"
    rm -rf "$work"
    chmod 600 "$tarf"
    sha256sum "$tarf" > "$tarf.sha256"
    good "Backup: $tarf ($(du -h "$tarf" | cut -f1))"

    if [[ ${ENCRYPT:-0} -eq 1 ]]; then
        openssl enc -aes-256-cbc -pbkdf2 -salt -in "$tarf" -out "$tarf.enc" && good "Encrypted copy: $tarf.enc  (decrypt: openssl enc -d -aes-256-cbc -pbkdf2 -in FILE -out out.tar.gz)"
    fi
}

latest() { ls -1t "$BDIR"/*.tar.gz 2>/dev/null | head -1; }

do_export() {
    local f; f=$(latest); [[ -n $f ]] || { bad "No backup yet"; exit 1; }
    scp -p "$f" "$f.sha256" $( [[ -f $f.enc ]] && echo "$f.enc" ) "$1" && good "Exported $(basename "$f") to $1"
}

do_restore() {
    local tarf=$1; shift
    [[ -f $tarf ]] || { bad "No such file $tarf"; exit 1; }
    [[ -f $tarf.sha256 ]] && { sha256sum -c "$tarf.sha256" || { bad "Checksum mismatch - backup may be tampered"; confirm "Restore anyway?" || exit 1; }; }
    if [[ $# -gt 0 ]]; then
        local p rel=(); for p in "$@"; do rel+=("${p#/}"); done
        confirm "Overwrite ${rel[*]} from $(basename "$tarf")?" || exit 0
        tar -xzpf "$tarf" -C / "${rel[@]}" && good "Restored ${rel[*]}"
    else
        warn "Full restore overwrites /etc, web roots, home dirs, etc."
        confirm "Restore EVERYTHING from $(basename "$tarf")?" || exit 0
        tar -xzpf "$tarf" -C / --exclude=db --exclude=packages.txt --exclude='*.rules' --exclude=root-crontab && good "Full restore complete - restart services"
    fi
}

do_restore_db() {
    local tarf=$1 w; w=$(mktemp -d)
    tar -xzf "$tarf" -C "$w" db 2>/dev/null || { bad "No db/ in backup"; exit 1; }
    [[ -s $w/db/mysql-all.sql ]] && confirm "Re-import MySQL dump?" && mysql < "$w/db/mysql-all.sql" && good "MySQL restored"
    [[ -s $w/db/postgres-all.sql ]] && confirm "Re-import PostgreSQL dump?" && su - postgres -c "psql -f $w/db/postgres-all.sql" >/dev/null && good "PostgreSQL restored"
    rm -rf "$w"
}

ENCRYPT=0
case ${1:-} in
    "")          do_backup ;;
    --encrypt)   ENCRYPT=1; do_backup ;;
    --export)    do_export "$2" ;;
    --list)      ls -lht "$BDIR"/*.tar.gz* 2>/dev/null || echo "none" ;;
    --restore)   shift; do_restore "$@" ;;
    --restore-db) do_restore_db "$2" ;;
    *) sed -n '2,9p' "$0" ;;
esac
