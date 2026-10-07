#!/usr/bin/env bash
# CyberForce Linux Toolkit - shared configuration
# EDIT THIS FIRST once you see your environment and the competition rules.

# Where all output (snapshots, backups, logs, reports) goes
CF_OUT="${CF_OUT:-/opt/cf}"

# Accounts the toolkit must NEVER lock, change, or strip cron jobs from
# (scoring / black-team / service accounts named in the rules packet)
CF_EXCLUDED_USERS=(root)          # e.g. (root scoring blackteam postgres)

# Team admins allowed to SSH in (used by 03-ssh-guard). Others are reported.
CF_SSH_ALLOWED_USERS=(root)       # e.g. (root sysadmin)

# Your team's management subnets (SSH is only allowed from these by the firewall)
CF_MGMT_SUBNETS=("10.0.0.0/24")

# Scored services on THIS box - inbound ports that must stay open to everyone
CF_ALLOWED_TCP=(80 443)           # web=80 443  dns=53  mail=25 110 143 587 993  ftp=21  mysql=3306
CF_ALLOWED_UDP=()                 # dns=53  ntp=123

# The scoring engine / black team IPs (always allowed, never blocked). Empty = none.
CF_TRUSTED_IPS=()

# Systemd services that are scored and must stay up (used by 01 and 11)
CF_SCORED_SERVICES=(ssh)          # e.g. (apache2 mysql bind9 vsftpd)

# Directories watched by 10-file-monitor
CF_WATCH_DIRS=(/etc /tmp /var/tmp /dev/shm /var/www /root /home /usr/local/bin)

# Extra paths for 04-backup (in addition to the defaults)
CF_BACKUP_EXTRA=()                # e.g. (/srv/app /opt/scada)

# Wazuh manager IP for agents (09-siem). Leave empty to run the manager on this box via Docker.
CF_WAZUH_MANAGER=""
# Port the Wazuh dashboard is published on by docker/wazuh (443 conflicts with web servers)
CF_WAZUH_DASH_PORT=8443
