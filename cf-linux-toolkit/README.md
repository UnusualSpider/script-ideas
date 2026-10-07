# CyberForce Linux Blue-Team Toolkit

Bash tooling for defending the Linux machines in a DOE CyberForce Competition.
Companion to the Windows/PowerShell toolkit. Tested syntax on Bash 5; works on
Debian/Ubuntu/Kali, RHEL/Rocky/Alma, Fedora, openSUSE, Arch and Alpine (package
manager auto-detected).

> **Read the competition rules first.** List the scoring/black-team/service accounts, the
> scored services, and the scoring-engine IPs in `config.sh` **before** you apply anything,
> or you will lock out the scoring engine and lose points. Test on your assigned box during
> the setup window.

## Layout

```
cf.sh              menu launcher (sudo ./cf.sh) + `sudo ./cf.sh S` safe setup sequence
config.sh          EDIT FIRST - accounts, subnets, ports, scored services, watch dirs
lib.sh             shared helpers (logging, package manager abstraction)
tools/01..15       the tools
docker/            containerized services (Wazuh, OpenVAS, Nikto/Wapiti, ClamAV) + service templates
```

## Quick start

```bash
sudo tar xzf cf-linux-toolkit.tar.gz   # or unzip the zip
cd cf-linux-toolkit
chmod +x cf.sh tools/*.sh docker/*/*.sh docker/*.sh
nano config.sh                         # <-- do this
sudo ./cf.sh S                         # snapshots, baselines, read-only scans, previews
```

All output goes to `/opt/cf` (`CF_OUT` in config.sh): snapshots, baselines, backups, reports, logs.

## Safety model

- **Read-only / snapshot:** 01, 05 `--snapshot/--diff`, 10 `--baseline/--scan`, 11, 13, 14 (report).
- **Preview-by-default (need a flag to change anything):** 06 (lists until `--nuke`), 07 (previews until `--apply`).
- **Destructive actions ask first** and **back up** before acting: cron nuke, firewall apply (60-second
  dead-man rollback so you can't lock yourself out), user restore, SUID/permission fixes.
- Every watchdog saves a "known-good" state you control; re-snapshot after *you* make a change,
  or the enforcer will revert it.

## The tools

| # | Tool | What it does |
|---|------|--------------|
| 01 | `machine-info` | Full host/service/network/user/port inventory → report |
| 02 | `install-tools` | Lynis, Nikto, Wapiti, otseca (local); OpenVAS via Docker; `--run-lynis`/`--run-otseca` audit now |
| 03 | `ssh-guard` | Harden sshd (validated, auto-rollback), install team keys, audit/purge rogue keys, 60s watchdog that restores config + kills unapproved keys |
| 04 | `backup` | Tarball of configs, web roots, homes, cron + DB dumps; `--encrypt`, `--export` off-box, selective `--restore` |
| 05 | `user-snapshot` | Snapshot passwd/shadow/group/sudoers; `--diff` drift; watchdog with optional `--enforce` auto-revert and rogue-session kill |
| 06 | `cron-nuke` | Inventory every cron/at/timer/anacron job, flag non-package & suspicious ones, `--nuke` (backs up), `--lock` to root-only |
| 07 | `firewall` | Default-deny inbound iptables: loopback/established/ICMP, SSH from mgmt subnet only, scored ports open, log+drop; `--auto`, `--egress`, dead-man rollback |
| 09 | `siem-wazuh` | Deploy Wazuh SIEM (`--manager` via Docker) and install agents (`--agent IP`) with extra realtime FIM |
| 10 | `file-monitor` | sha256 integrity baseline + scan; live inotify watch (`--watch-install`); `--auditd` who-touched-what rules |
| 11 | `process-monitor` | Flag reverse shells, deleted-binary processes, temp-dir execs, unexpected listeners, reparented shells |
| 12 | `malware-scanner` | Install + run ClamAV, rkhunter, chkrootkit, maldet; `--docker` for containerized ClamAV |
| 13 | `tcp-monitor` | Active/listening/established/outbound TCP sessions with process + user, external-talker flagging, `--kill IP` |
| 14 | `suid-worldwritable` | SUID/SGID (vs baseline), world-writable files/dirs, no-owner files, writable PATH/units/sudoers, weak .ssh perms; `--fix-ww`/`--fix-suid` |
| 15 | `firewall-persist` | Persist the firewall across reboots (netfilter-persistent or systemd) + watchdog that re-applies rules if flushed |

## Docker (`docker/`)

"Dockerify all possible services" - these containerize the security stack and give you a clean,
redeployable version of your scored services:

- `docker/wazuh/setup.sh` - Wazuh single-node SIEM (manager + indexer + dashboard), pinned `v4.14.8`,
  dashboard on port `8443` so it doesn't clash with a web server. Needs ~8 GB RAM; sets `vm.max_map_count`.
- `docker/openvas/setup.sh` - Greenbone/OpenVAS vulnerability scanner from the official compose file,
  web UI on `:9392`, sets a random admin password (saved to `/opt/cf-openvas/admin-password.txt`).
- `docker/scanners/scan.sh nikto|wapiti|both URL` - run the web scanners from containers, no local install.
- `docker/clamav/setup.sh PATH` - ClamAV daemon container scanning a read-only mount.
- `docker/services/` - **templates** to run your *scored* services (web/db/dns/ftp/mail) in containers.
  - `dockerize.sh --detect` sees what the box runs and where its config lives.
  - `dockerize.sh --scaffold` copies the current config/content/DB into mountable folders.
  - `dockerize.sh --up web db` stops the native service and brings up the container on the same port.
  - Why: a compromised container is thrown away and redeployed from a pinned image in seconds, while
    your data stays on the mounted volume. Review the compose file and copied config before `--up`.

## Suggested game plan

**Setup window**
1. Edit `config.sh` for this box's role.
2. `sudo ./cf.sh S` - inventory, backup, and every baseline/snapshot; previews cron + firewall.
3. Keep your access: `tools/03-ssh-guard.sh --harden --add-key team.pub`, then `--watchdog-install`.
4. Clean up: `tools/06-cron-nuke.sh --nuke`, `tools/14-...sh` then `--fix-suid`/`--fix-ww`.
5. Lock down: `tools/07-firewall.sh --apply` → confirm you still have SSH → `tools/15-...sh --install --watchdog`.
6. Turn on guards: `05 --watchdog-install --enforce`, `10 --watch-install` + `--auditd`.
7. SIEM: `docker/wazuh/setup.sh` on one box, `09 --agent <ip>` on the rest.
8. Scan: `12 --install --update --scan`, and OpenVAS/Nikto/Wapiti from `docker/`.
9. **Re-run all `--baseline`/`--snapshot` after hardening**, and copy `/opt/cf/backup` off-box.

**Attack phase** - keep these running in separate panes (tmux):
- `tools/11-process-monitor.sh --watch` · `tools/13-tcp-monitor.sh --watch` · `tail -f /opt/cf/filemon/events.log`
- Every few minutes: `tools/10-file-monitor.sh --scan`, `tools/05-user-snapshot.sh --diff`, `tools/14-suid-worldwritable.sh --suid`
- Wazuh dashboard for the whole-team view. Use `04-backup.sh --restore` / `--restore-db` to recover defaced or wiped services.

## Notes & gotchas

- `--egress` (outbound filtering in 07) stops reverse shells but can break updates, DNS, or app callbacks. Test it.
- The firewall only manages the INPUT/OUTPUT chains; Docker's own FORWARD/NAT rules are left alone.
- Wazuh and OpenVAS pull large images and sync large feeds on first run - start them early in the setup window.
- `config.sh`'s `CF_EXCLUDED_USERS` protects accounts from password/cron/user actions. Get it right first.
- These are Linux-only; use the PowerShell toolkit for Windows hosts (both can report to the same Wazuh manager).
