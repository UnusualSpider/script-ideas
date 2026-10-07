<#
.SYNOPSIS
    06 - Logging: turn on the audit trail, then query it for attacker activity.
.DESCRIPTION
    -Enable  : advanced audit policy, command-line in 4688, PowerShell script block /
               module / transcription logging, bigger event logs.
    (default): read-only report of the last -Hours of security-relevant events:
       4624/4625 logons (failed + network/RDP), 4720 user created, 4722 enabled,
       4724 password reset, 4728/4732/4756 added to group, 4698 scheduled task,
       7045 new service, 1102/104 log cleared, 4104 suspicious PowerShell,
       Defender detections (1116/1117).
.EXAMPLE
    .\06-Logging.ps1 -Enable
    .\06-Logging.ps1 -Hours 2
    .\06-Logging.ps1 -Hours 1 -Export
#>
[CmdletBinding()]
param(
    [switch]$Enable,
    [double]$Hours = 1,
    [switch]$Export
)

. (Join-Path $PSScriptRoot '..\Config.ps1')
if (-not (Test-CFAdmin)) { Write-CF 'Run as Administrator.' Bad; return }

if ($Enable) {
    $sub = @(
        'Credential Validation', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations',
        'User Account Management', 'Security Group Management', 'Computer Account Management',
        'Logon', 'Logoff', 'Account Lockout', 'Special Logon',
        'Process Creation', 'Security System Extension', 'System Integrity',
        'Audit Policy Change', 'Authentication Policy Change',
        'Sensitive Privilege Use', 'Other Object Access Events', 'File Share',
        'Directory Service Changes', 'Directory Service Access'
    )
    foreach ($s in $sub) {
        $out = auditpol /set /subcategory:"$s" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) { Write-CF "Audit: $s" Good } else { Write-CF "Audit: $s skipped ($out)" Warn }
    }
    # Force advanced audit policy to override legacy categories
    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -PropertyType DWord -Force | Out-Null
    # Command line in process-creation events
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item $k -Force | Out-Null
    New-ItemProperty $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
    Write-CF 'Process command lines included in 4688' Good

    # PowerShell logging
    $ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    New-Item "$ps\ScriptBlockLogging" -Force | Out-Null
    New-ItemProperty "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
    New-Item "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
    New-ItemProperty "$ps\ModuleLogging" -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty "$ps\ModuleLogging\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
    $tdir = Get-CFDir 'pstranscripts'
    New-Item "$ps\Transcription" -Force | Out-Null
    New-ItemProperty "$ps\Transcription" -Name EnableTranscripting -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty "$ps\Transcription" -Name EnableInvocationHeader -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty "$ps\Transcription" -Name OutputDirectory -Value $tdir -PropertyType String -Force | Out-Null
    Write-CF "PowerShell script block, module and transcription logging ON (transcripts in $tdir)" Good

    # Bigger logs so the Red team can't roll them over quickly
    foreach ($log in 'Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell') {
        wevtutil sl "$log" /ms:536870912 2>$null   # 512 MB
        if ($LASTEXITCODE -eq 0) { Write-CF "Log size 512MB: $log" Good }
    }
    Write-CF 'Logging enabled. Run without -Enable to query events.' Info
    return
}

# ---------------------------------------------------------------- query
$start = (Get-Date).AddHours(-$Hours)
$rows = New-Object System.Collections.Generic.List[object]

function Get-CFEvents {
    param([string]$Log, [int[]]$Ids)
    try {
        Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Ids; StartTime = $start } -ErrorAction Stop
    } catch { @() }
}

function Get-CFField { param($Evt, [string]$Field)
    $xml = [xml]$Evt.ToXml()
    ($xml.Event.EventData.Data | Where-Object Name -eq $Field).'#text'
}

function Add-CFRow { param($Time, $Id, $What, $Detail, $Level = 'Warn')
    $rows.Add([pscustomobject]@{ Time = $Time; EventId = $Id; What = $What; Detail = $Detail })
    Write-CF ("{0:HH:mm:ss} [{1}] {2} - {3}" -f $Time, $Id, $What, $Detail) $Level
}

Write-CF "==== Security events since $start on $env:COMPUTERNAME ===="

# Failed logons, grouped
$fail = Get-CFEvents 'Security' 4625
if ($fail) {
    $fail | ForEach-Object { [pscustomobject]@{ User = (Get-CFField $_ 'TargetUserName'); Ip = (Get-CFField $_ 'IpAddress') } } |
        Group-Object User, Ip | Sort-Object Count -Descending | Select-Object -First 15 |
        ForEach-Object { Add-CFRow $start 4625 'Failed logons' "$($_.Name) x$($_.Count)" }
}

# Successful network / RDP logons
foreach ($e in Get-CFEvents 'Security' 4624) {
    $type = Get-CFField $e 'LogonType'
    if ($type -in '3', '10') {
        $user = Get-CFField $e 'TargetUserName'
        if ($user -match '\$$' -or $user -eq 'ANONYMOUS LOGON') { continue }
        $t = if ($type -eq '10') { 'RDP logon' } else { 'Network logon' }
        Add-CFRow $e.TimeCreated 4624 $t "$user from $(Get-CFField $e 'IpAddress')" Info
    }
}

$map = @{
    4720 = 'User created'; 4722 = 'User enabled'; 4724 = 'Password reset'; 4738 = 'User changed'
    4728 = 'Added to global group'; 4732 = 'Added to local group'; 4756 = 'Added to universal group'
    4698 = 'Scheduled task created'; 4702 = 'Scheduled task updated'; 1102 = 'SECURITY LOG CLEARED'
}
foreach ($e in Get-CFEvents 'Security' ([int[]]$map.Keys)) {
    $detail = switch ($e.Id) {
        { $_ -in 4728, 4732, 4756 } { "$(Get-CFField $e 'MemberName') -> $(Get-CFField $e 'TargetUserName') by $(Get-CFField $e 'SubjectUserName')" }
        { $_ -in 4698, 4702 }       { "$(Get-CFField $e 'TaskName') by $(Get-CFField $e 'SubjectUserName')" }
        1102                        { 'Audit log was cleared' }
        default                     { "$(Get-CFField $e 'TargetUserName') by $(Get-CFField $e 'SubjectUserName')" }
    }
    Add-CFRow $e.TimeCreated $e.Id $map[$e.Id] $detail 'Bad'
}

foreach ($e in Get-CFEvents 'System' 7045) {
    Add-CFRow $e.TimeCreated 7045 'Service installed' "$(Get-CFField $e 'ServiceName') -> $(Get-CFField $e 'ImagePath')" 'Bad'
}
foreach ($e in Get-CFEvents 'System' 104) { Add-CFRow $e.TimeCreated 104 'EVENT LOG CLEARED' $e.Message 'Bad' }

# Suspicious PowerShell script blocks
$sus = '(?i)(frombase64string|downloadstring|downloadfile|invoke-expression|iex\s*\(|net\.webclient|invoke-mimikatz|sekurlsa|amsiutils|-enc\s|bypass|reflection\.assembly|new-object\s+system\.net\.sockets)'
foreach ($e in Get-CFEvents 'Microsoft-Windows-PowerShell/Operational' 4104) {
    $text = Get-CFField $e 'ScriptBlockText'
    if ($text -match $sus) {
        $snip = ($text -replace '\s+', ' ')
        if ($snip.Length -gt 200) { $snip = $snip.Substring(0, 200) + '...' }
        Add-CFRow $e.TimeCreated 4104 'Suspicious PowerShell' $snip 'Bad'
    }
}

# Defender detections
foreach ($e in Get-CFEvents 'Microsoft-Windows-Windows Defender/Operational' 1116, 1117, 5001) {
    $what = @{ 1116 = 'Defender detection'; 1117 = 'Defender action'; 5001 = 'DEFENDER REAL-TIME DISABLED' }[$e.Id]
    Add-CFRow $e.TimeCreated $e.Id $what (($e.Message -split "`n")[0..3] -join ' ') 'Bad'
}

Write-CF "$($rows.Count) event row(s)." Info
if ($Export -and $rows.Count) {
    $f = Join-Path (Get-CFDir 'reports') ("events-{0}-{1}.csv" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $rows | Sort-Object Time | Export-Csv $f -NoTypeInformation
    Write-CF "Exported to $f (useful for incident reports)" Good
}
