# CyberForce Blue Team Toolkit (Windows / PowerShell)

PowerShell scripts for defending the Windows side of a DOE CyberForce Competition environment.
Works on Windows Server 2012 R2+ and Windows 10/11 with Windows PowerShell 5.1.

> **Read the competition rules first.** They list accounts, services, and IPs you must not touch
> (scoring and black-team access). Put those in `Config.ps1` before applying anything.
> Test every script on your assigned environment during the setup window, not on game day.

## Quick start

```powershell
# Elevated PowerShell, from the toolkit folder
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ChildItem -Recurse *.ps1 | Unblock-File
notepad .\Config.ps1          # set excluded accounts, approved admins, ports, scored checks
.\Start-CyberForce.ps1        # menu; option 0 runs the safe "first 10 minutes" set
```

All output goes to `C:\CF\` (change `$CF_OutputRoot` in `Config.ps1`).

## Safety design

- Anything that changes the system (**02, 04, 05**) is a **dry run unless you pass `-Apply`**.
- **04** exports the firewall policy before changing it → `-Restore`.
- **05** records every registry value it changes → `-Rollback`.
- **02** never touches accounts in `$CF_ExcludedAccounts`, and only *reports* unapproved admins
  unless you add `-RemoveUnapprovedAdmins`.
- **01, 03, 06 (query), 07 (without -AutoFix)** are read-only.

## The tools

| # | Script | What it does | Common use |
|---|--------|--------------|------------|
| 01 | `01-Baseline.ps1` | Snapshot of users, groups, services, ports, processes, tasks, Run keys, WMI subs, shares, software, firewall, AD/GPOs (DC) | Run first, and again after you finish hardening |
| 02 | `02-AccountLockdown.ps1` | Rotate passwords (saved to `C:\CF\secrets`), disable Guest, review/prune admin groups, password + lockout policy, Kerberoast/AS-REP report | `-Apply`, `-Users a,b`, `-RemoveUnapprovedAdmins`, `-SkipPasswords` |
| 03 | `03-HuntPersistence.ps1` | Diff against baseline + heuristics: new users/admins/services/tasks/Run keys/ports/shares, WMI consumers, sticky-keys/IFEO hijacks, encoded PowerShell, Defender exclusions, dropped files | `-Loop 300` to re-hunt every 5 min |
| 04 | `04-Firewall.ps1` | Default-deny inbound, allow scored ports, RDP/WinRM only from mgmt subnet, log drops | `-Apply`, `-DisableOtherInbound`, `-Panic`, `-Restore` |
| 05 | `05-Harden.ps1` | SMBv1 off, SMB signing, LLMNR/NetBIOS/WPAD off, WDigest off, LSA protection, NTLMv2-only, anonymous restrictions, RDP NLA, UAC, AutoRun off, Defender on + update, Spooler off | `-Apply`, `-KeepSpooler`, `-SkipLsaProtection`, `-SkipNtlmV2Only`, `-ClearDefenderExclusions`, `-Rollback` |
| 06 | `06-Logging.ps1` | `-Enable`: advanced audit policy, 4688 command lines, PowerShell logging + transcripts, 512 MB logs. Default: report of logons, account/group changes, new tasks/services, log clears, suspicious PowerShell, Defender hits | `-Hours 2 -Export` for incident reports |
| 07 | `07-ServiceCheck.ps1` | Health-check scored services (Service / Http / Tcp), auto-restart, web-root defacement and webshell detection, uptime CSV | `-Loop -AutoFix -WebRoot C:\inetpub\wwwroot` |
| 08 | `08-BackupRestore.ps1` | Back up web roots, IIS config, GPOs, AD export, DNS zones, hosts, firewall, tasks. Restore web/IIS/GPO/hosts; undelete AD objects | `-Paths C:\app`, `-RestoreWeb`, `-RestoreADObject jsmith` |

## Suggested game plan

**Setup window (before the attack phase)**
1. Edit `Config.ps1` for each host role (DC, web, file, HMI jump box…).
2. `01-Baseline` → `08-BackupRestore` → `06-Logging -Enable`.
3. Preview, then apply: `02 -Apply`, `05 -Apply`, `04 -Apply`.
4. `07-ServiceCheck` – confirm every scored service is still up after each change.
5. Run `01-Baseline` again so the hunt diffs against your *hardened* state.
6. Copy `C:\CF\backup` and `C:\CF\secrets` off the box.

**During the attack phase**
- Keep `07-ServiceCheck -Loop -AutoFix` running in its own window on each server.
- Run `03-HuntPersistence` every few minutes (or `-Loop 300`).
- Run `06-Logging -Hours 1 -Export` to build evidence for incident reports.
- Defaced site? `08 -RestoreWeb`. Deleted user? `08 -RestoreADObject <name>`.
- Something broke after hardening? `05 -Rollback` / `04 -Restore`.

## Things to know

- **LSA protection** (`RunAsPPL`) needs a reboot and can block some third-party security software. Skip it with `-SkipLsaProtection` if a reboot isn't allowed.
- **NTLMv2-only** can break very old clients or ICS/HMI software. Use `-SkipNtlmV2Only` on those hosts.
- **Firewall on a DC** needs many ports (53, 88, 135, 389, 445, 464, 636, 3268/3269, and the dynamic RPC range `'49152-65535'`). Uncomment the DC line in `Config.ps1`.
- `05 -Rollback` restores registry values only. Services and SMB server settings must be re-enabled by hand (`Set-Service`, `Set-SmbServerConfiguration`).
- The Linux boxes need their own (bash) equivalents. These scripts are Windows-only.
- `C:\CF\secrets` holds plaintext passwords after `02 -Apply`. Move it off the box and delete it.
