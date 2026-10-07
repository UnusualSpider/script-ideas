#!/usr/bin/env bash
# Shared helpers - sourced by every tool. Do not run directly.

CF_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "$CF_ROOT/config.sh"

C_RESET=$'\e[0m'; C_CYAN=$'\e[36m'; C_GREEN=$'\e[32m'; C_YEL=$'\e[33m'; C_RED=$'\e[31m'
[[ -t 1 ]] || { C_RESET=; C_CYAN=; C_GREEN=; C_YEL=; C_RED=; }

mkdir -p "$CF_OUT" 2>/dev/null
CF_LOG="$CF_OUT/toolkit.log"

_log() { # level color msg
    local line
    line="[$(date +%H:%M:%S)] [$1] $3"
    printf '%s%s%s\n' "$2" "$line" "$C_RESET"
    echo "$line" >> "$CF_LOG" 2>/dev/null || true
}
info() { _log INFO "$C_CYAN"  "$*"; }
good() { _log GOOD "$C_GREEN" "$*"; }
warn() { _log WARN "$C_YEL"   "$*"; }
bad()  { _log BAD  "$C_RED"   "$*"; }

need_root() { [[ $EUID -eq 0 ]] || { bad "Run as root (sudo $0 $*)"; exit 1; }; }
have()      { command -v "$1" >/dev/null 2>&1; }
stamp()     { date +%Y%m%d-%H%M%S; }
outdir()    { mkdir -p "$CF_OUT/$1" && echo "$CF_OUT/$1"; }

is_excluded() { local u; for u in "${CF_EXCLUDED_USERS[@]}"; do [[ "$u" == "$1" ]] && return 0; done; return 1; }

# Distro / package manager detection
detect_pm() {
    if   have apt-get; then PM=apt
    elif have dnf;     then PM=dnf
    elif have yum;     then PM=yum
    elif have zypper;  then PM=zypper
    elif have pacman;  then PM=pacman
    elif have apk;     then PM=apk
    else PM=none; fi
    export PM
}
pkg_install() {
    detect_pm
    case $PM in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
        dnf)    dnf install -y "$@" ;;
        yum)    yum install -y "$@" ;;
        zypper) zypper --non-interactive install "$@" ;;
        pacman) pacman -S --noconfirm --needed "$@" ;;
        apk)    apk add "$@" ;;
        *)      bad "No supported package manager"; return 1 ;;
    esac
}
pkg_remove() {
    detect_pm
    case $PM in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get purge -y "$@" ;;
        dnf)    dnf remove -y "$@" ;;
        yum)    yum remove -y "$@" ;;
        zypper) zypper --non-interactive remove "$@" ;;
        pacman) pacman -Rns --noconfirm "$@" ;;
        apk)    apk del "$@" ;;
    esac
}
pkg_update() {
    detect_pm
    case $PM in
        apt) apt-get update -y ;; dnf|yum) $PM makecache -y ;; zypper) zypper refresh ;;
        pacman) pacman -Sy ;; apk) apk update ;;
    esac
}
pkg_installed() {
    detect_pm
    case $PM in
        apt) dpkg -s "$1" >/dev/null 2>&1 ;;
        dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
        pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
        apk) apk info -e "$1" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

svc_name_ssh() { systemctl list-unit-files 2>/dev/null | grep -qE '^sshd\.service' && echo sshd || echo ssh; }

# Simple yes/no prompt (default No)
confirm() { local a; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }
