<#
.SYNOPSIS
    01 - Inventory & baseline. Run FIRST, before the Red team is active.
.DESCRIPTION
    Snapshots users, groups, services, listening ports, processes, scheduled tasks,
    autoruns, shares, installed software, firewall rules and (on a DC) AD objects
    into timestamped CSV/JSON files. 03-HuntPersistence.ps1 diffs against the newest baseline.
.EXAMPLE
    .\01-Baseline.ps1
#>
[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot '..\Config.ps1')
if (-not (Test-CFAdmin)) { Write-CF 'Run as Administrator.' Bad; return }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dir   = Get-CFDir "baseline\$env:COMPUTERNAME-$stamp"
Write-CF "Writing baseline to $dir"

function Save-CF {
    param([string]$Name, [scriptblock]$Block)
    try {
        $data = & $Block
        $data | Export-Csv -Path (Join-Path $dir "$Name.csv") -NoTypeInformation -Encoding UTF8
        Write-CF ("{0,-18} {1} rows" -f $Name, @($data).Count) Good
    } catch {
        Write-CF "$Name failed: $($_.Exception.Message)" Warn
    }
}

# --- System info ---
Save-CF 'system' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    [pscustomobject]@{
        Hostname   = $env:COMPUTERNAME
        Domain     = $cs.Domain
        DomainRole = $cs.DomainRole
        OS         = $os.Caption
        Version    = $os.Version
        LastBoot   = $os.LastBootUpTime
        IPs        = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -ne '127.0.0.1').IPAddress -join ';'
    }
}

# --- Local users & groups ---
Save-CF 'local_users' {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, PasswordExpires, Description, SID
}
Save-CF 'local_groups' {
    foreach ($g in Get-LocalGroup) {
        try {
            foreach ($m in Get-LocalGroupMember -Group $g.Name -ErrorAction Stop) {
                [pscustomobject]@{ Group = $g.Name; Member = $m.Name; Class = $m.ObjectClass; Source = $m.PrincipalSource }
            }
        } catch {
            # Get-LocalGroupMember breaks on orphaned SIDs - fall back to ADSI
            $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$($g.Name),group"
            foreach ($m in @($adsi.Invoke('Members'))) {
                [pscustomobject]@{ Group = $g.Name; Member = $m.GetType().InvokeMember('Name','GetProperty',$null,$m,$null); Class = 'unknown'; Source = 'ADSI' }
            }
        }
    }
}

# --- Domain (DC only) ---
if (Test-CFIsDC) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Save-CF 'ad_users' {
        Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, AdminCount, MemberOf, ServicePrincipalName, Description |
            Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet, AdminCount,
                @{n='SPNs';e={$_.ServicePrincipalName -join ';'}}, Description, DistinguishedName
    }
    Save-CF 'ad_priv_groups' {
        foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','DnsAdmins','Group Policy Creator Owners') {
            try {
                Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop |
                    Select-Object @{n='Group';e={$g}}, SamAccountName, objectClass
            } catch {}
        }
    }
    Save-CF 'ad_computers' { Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate | Select-Object Name, OperatingSystem, LastLogonDate, Enabled }
    Save-CF 'gpos' { Get-GPO -All | Select-Object DisplayName, Id, GpoStatus, ModificationTime }
}

# --- Services ---
Save-CF 'services' {
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
}

# --- Network ---
Save-CF 'listening_tcp' {
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess, @{n='Process';e={$procs[[int]$_.OwningProcess]}}
}
Save-CF 'listening_udp' {
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    Get-NetUDPEndpoint | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess, @{n='Process';e={$procs[[int]$_.OwningProcess]}}
}
Save-CF 'established_tcp' {
    Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
}
Save-CF 'shares' { Get-SmbShare | Select-Object Name, Path, Description }
Save-CF 'firewall_rules' {
    Get-NetFirewallRule -Enabled True | Select-Object DisplayName, Direction, Action, Profile, Group
}

# --- Processes ---
Save-CF 'processes' {
    Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
}

# --- Persistence locations (also used by the hunt script) ---
Save-CF 'scheduled_tasks' {
    Get-ScheduledTask | ForEach-Object {
        [pscustomobject]@{
            TaskPath = $_.TaskPath; TaskName = $_.TaskName; State = $_.State
            Author   = $_.Author;   RunAs    = $_.Principal.UserId
            Actions  = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        }
    }
}
Save-CF 'autoruns' {
    $keys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            $p = Get-ItemProperty $k
            $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
                ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Value = $_.Value } }
        }
    }
    $wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    [pscustomobject]@{ Key = 'Winlogon'; Name = 'Userinit'; Value = $wl.Userinit }
    [pscustomobject]@{ Key = 'Winlogon'; Name = 'Shell';    Value = $wl.Shell }
    foreach ($f in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup") {
        if (Test-Path $f) { Get-ChildItem $f -Force | ForEach-Object { [pscustomobject]@{ Key = 'StartupFolder'; Name = $_.Name; Value = $_.FullName } } }
    }
}
Save-CF 'wmi_subscriptions' {
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Select-Object @{n='Filter';e={$_.Filter.Name}}, @{n='Consumer';e={$_.Consumer.Name}}
}

# --- Software ---
Save-CF 'installed_software' {
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
        Where-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}
Save-CF 'hotfixes' { Get-HotFix | Select-Object HotFixID, Description, InstalledOn }

# Mark this as the newest baseline for the hunt script
Set-Content -Path (Join-Path $Global:CF_OutputRoot 'baseline\LATEST.txt') -Value $dir
Write-CF "Baseline complete: $dir" Good
