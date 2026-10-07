<#
.SYNOPSIS
    03 - Persistence hunt: diff the box against the newest baseline and flag suspicious items.
.DESCRIPTION
    Read-only. Reports NEW / CHANGED items since 01-Baseline.ps1 in:
      users, admin group members, services, scheduled tasks, Run keys/startup/Winlogon,
      WMI subscriptions, listening ports, shares
    plus heuristic red flags (encoded PowerShell, binaries in Temp/ProgramData/Public,
    sticky-keys / IFEO debugger hijacks, Defender exclusions, unsigned service binaries).
.PARAMETER BaselineDir
    Baseline folder to compare to (default: newest).
.PARAMETER Loop
    Re-run every N seconds (0 = once).
.EXAMPLE
    .\03-HuntPersistence.ps1
    .\03-HuntPersistence.ps1 -Loop 300
#>
[CmdletBinding()]
param(
    [string]$BaselineDir,
    [int]$Loop = 0
)

. (Join-Path $PSScriptRoot '..\Config.ps1')
if (-not (Test-CFAdmin)) { Write-CF 'Run as Administrator.' Bad; return }

if (-not $BaselineDir) {
    $latest = Join-Path $Global:CF_OutputRoot 'baseline\LATEST.txt'
    if (Test-Path $latest) { $BaselineDir = (Get-Content $latest -Raw).Trim() }
}
if (-not $BaselineDir -or -not (Test-Path $BaselineDir)) {
    Write-CF 'No baseline found - run 01-Baseline.ps1 first. Continuing with heuristics only.' Warn
    $BaselineDir = $null
}

$suspiciousPath = '\\(Temp|tmp|ProgramData|Users\\Public|AppData|PerfLogs|Windows\\Tasks|Recycle)\\|\.(ps1|vbs|js|jse|hta|bat|cmd|scr)(\s|"|$)'
$suspiciousCmd  = '(?i)(-enc(odedcommand)?\s|frombase64string|iex\s*\(|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|bitsadmin|certutil.+-urlcache|mshta|regsvr32.+/i:http|rundll32.+javascript|nc(\.exe)?\s+-e|bash\s+-i|/dev/tcp)'

function Compare-CF {
    param([string]$Name, [object[]]$Current, [string]$Key)
    if (-not $BaselineDir) { return }
    $f = Join-Path $BaselineDir "$Name.csv"
    if (-not (Test-Path $f)) { return }
    $old = Import-Csv $f
    $oldKeys = @{}; foreach ($o in $old) { $oldKeys[[string]$o.$Key] = $o }
    foreach ($c in $Current) {
        $k = [string]$c.$Key
        if (-not $oldKeys.ContainsKey($k)) {
            Write-CF ("NEW {0}: {1}" -f $Name, ($c | Out-String).Trim() -replace '\s+', ' ') Bad
            $script:findings++
        }
    }
    $curKeys = @{}; foreach ($c in $Current) { $curKeys[[string]$c.$Key] = $true }
    foreach ($o in $old) {
        if (-not $curKeys.ContainsKey([string]$o.$Key)) { Write-CF ("REMOVED {0}: {1}" -f $Name, $o.$Key) Warn }
    }
}

function Invoke-Hunt {
    $script:findings = 0
    Write-CF "==== Persistence hunt on $env:COMPUTERNAME (baseline: $BaselineDir) ===="

    # Users
    $users = Get-LocalUser | Select-Object Name, Enabled
    Compare-CF 'local_users' $users 'Name'
    if (Test-CFIsDC) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adu = Get-ADUser -Filter * | Select-Object SamAccountName
        Compare-CF 'ad_users' $adu 'SamAccountName'
        $recent = Get-ADUser -Filter * -Properties whenCreated | Where-Object whenCreated -gt (Get-Date).AddHours(-24)
        foreach ($r in $recent) { Write-CF "AD user created in last 24h: $($r.SamAccountName) at $($r.whenCreated)" Warn }
    }

    # Admin group members
    $adm = foreach ($g in 'Administrators', 'Remote Desktop Users', 'Remote Management Users') {
        Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ Group = $g; Member = $_.Name; Key = "$g|$($_.Name)" }
        }
    }
    if ($BaselineDir -and (Test-Path (Join-Path $BaselineDir 'local_groups.csv'))) {
        $old = Import-Csv (Join-Path $BaselineDir 'local_groups.csv') | ForEach-Object { "$($_.Group)|$($_.Member)" }
        foreach ($a in $adm) { if ($old -notcontains $a.Key) { Write-CF "NEW member of $($a.Group): $($a.Member)" Bad; $script:findings++ } }
    }

    # Services
    $svcs = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    Compare-CF 'services' $svcs 'Name'
    foreach ($s in $svcs) {
        if ($s.PathName -match $suspiciousPath -or $s.PathName -match $suspiciousCmd) {
            Write-CF "Suspicious service path: $($s.Name) -> $($s.PathName)" Bad; $script:findings++
        }
    }

    # Scheduled tasks
    $tasks = Get-ScheduledTask | ForEach-Object {
        [pscustomobject]@{
            FullName = "$($_.TaskPath)$($_.TaskName)"; TaskPath = $_.TaskPath; TaskName = $_.TaskName
            RunAs = $_.Principal.UserId
            Actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        }
    }
    if ($BaselineDir -and (Test-Path (Join-Path $BaselineDir 'scheduled_tasks.csv'))) {
        $old = Import-Csv (Join-Path $BaselineDir 'scheduled_tasks.csv') | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }
        foreach ($t in $tasks) { if ($old -notcontains $t.FullName) { Write-CF "NEW scheduled task: $($t.FullName) [$($t.RunAs)] -> $($t.Actions)" Bad; $script:findings++ } }
    }
    foreach ($t in $tasks) {
        if ($t.Actions -match $suspiciousCmd -or ($t.TaskPath -notlike '\Microsoft\*' -and $t.Actions -match $suspiciousPath)) {
            Write-CF "Suspicious task action: $($t.FullName) -> $($t.Actions)" Bad; $script:findings++
        }
    }

    # Autoruns
    $keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    $runs = foreach ($k in $keys) {
        if (Test-Path $k) {
            (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
                ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Value = $_.Value; Id = "$k|$($_.Name)" } }
        }
    }
    if ($BaselineDir -and (Test-Path (Join-Path $BaselineDir 'autoruns.csv'))) {
        $old = Import-Csv (Join-Path $BaselineDir 'autoruns.csv') | ForEach-Object { "$($_.Key)|$($_.Name)" }
        foreach ($r in $runs) { if ($old -notcontains $r.Id) { Write-CF "NEW Run key: $($r.Key)\$($r.Name) = $($r.Value)" Bad; $script:findings++ } }
    }
    $wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Write-CF "Winlogon Userinit modified: $($wl.Userinit)" Bad; $script:findings++ }
    if ($wl.Shell -ne 'explorer.exe') { Write-CF "Winlogon Shell modified: $($wl.Shell)" Bad; $script:findings++ }

    # Startup folders
    foreach ($f in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
        Get-ChildItem $f -Force -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini' |
            ForEach-Object { Write-CF "Startup folder item: $($_.FullName)" Warn }
    }

    # Accessibility / IFEO hijacks (sticky keys backdoor)
    foreach ($exe in 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe') {
        $ifeo = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
        $dbg = (Get-ItemProperty $ifeo -ErrorAction SilentlyContinue).Debugger
        if ($dbg) { Write-CF "IFEO debugger hijack on ${exe}: $dbg" Bad; $script:findings++ }
        $p = Join-Path $env:windir "System32\$exe"
        if (Test-Path $p) {
            $sig = Get-AuthenticodeSignature $p
            $desc = (Get-Item $p).VersionInfo.FileDescription
            if ($sig.Status -ne 'Valid' -or $desc -match 'Command Processor|PowerShell') {
                Write-CF "$exe looks replaced (sig=$($sig.Status), desc=$desc)" Bad; $script:findings++
            }
        }
    }

    # WMI subscriptions
    $wmi = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
    foreach ($w in $wmi) {
        if ($w.Name -ne 'SCM Event Log Consumer') {
            Write-CF "WMI event consumer: $($w.Name) [$($w.CimClass.CimClassName)] $($w.CommandLineTemplate)$($w.ScriptText)" Bad; $script:findings++
        }
    }

    # Network
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    $listen = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, @{n='Process';e={$procs[[int]$_.OwningProcess]}}, @{n='Id';e={"$($_.LocalAddress):$($_.LocalPort)"}}
    if ($BaselineDir -and (Test-Path (Join-Path $BaselineDir 'listening_tcp.csv'))) {
        $old = Import-Csv (Join-Path $BaselineDir 'listening_tcp.csv') | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }
        foreach ($l in $listen) {
            if ($old -notcontains $l.Id -and [int]$l.LocalPort -lt 49152) { Write-CF "NEW listening port: $($l.Id) ($($l.Process))" Bad; $script:findings++ }
        }
    }
    Compare-CF 'shares' (Get-SmbShare | Select-Object Name, Path) 'Name'

    # Running processes with suspicious command lines
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match $suspiciousCmd } | ForEach-Object {
        Write-CF "Suspicious process PID $($_.ProcessId) [$($_.Name)]: $($_.CommandLine)" Bad; $script:findings++
    }

    # Defender tampering
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        if ($mp.ExclusionPath -or $mp.ExclusionProcess -or $mp.ExclusionExtension) {
            Write-CF "Defender exclusions present: $($mp.ExclusionPath -join ', ') $($mp.ExclusionProcess -join ', ') $($mp.ExclusionExtension -join ', ')" Bad; $script:findings++
        }
        if ($mp.DisableRealtimeMonitoring) { Write-CF 'Defender real-time monitoring is DISABLED' Bad; $script:findings++ }
    } catch {}

    # Recently dropped executables
    $since = (Get-Date).AddHours(-6)
    foreach ($d in "$env:windir\Temp", "$env:ProgramData", "C:\Users\Public", "C:\PerfLogs") {
        Get-ChildItem $d -Recurse -Force -File -ErrorAction SilentlyContinue -Include *.exe, *.dll, *.ps1, *.bat, *.vbs, *.hta |
            Where-Object { $_.LastWriteTime -gt $since -and $_.FullName -notmatch '\\Microsoft\\Windows Defender\\' } |
            Select-Object -First 25 | ForEach-Object { Write-CF "Recent file: $($_.FullName) ($($_.LastWriteTime))" Warn }
    }

    $lvl = if ($script:findings) { 'Bad' } else { 'Good' }
    Write-CF "Hunt complete - $($script:findings) high-priority finding(s)." $lvl
}

do {
    Invoke-Hunt
    if ($Loop -gt 0) { Start-Sleep -Seconds $Loop }
} while ($Loop -gt 0)
