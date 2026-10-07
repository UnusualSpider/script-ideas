<#
.SYNOPSIS
    05 - Windows hardening bundle with rollback.
.DESCRIPTION
    DRY RUN BY DEFAULT. Pass -Apply to change settings.
    Every registry value is recorded before it changes (C:\CF\harden\rollback-*.json)
    so -Rollback can undo the last run.

    Settings:
      SMBv1 off, SMB signing required, SMB guest/anonymous access off
      LLMNR off, NetBIOS over TCP/IP off, WPAD off
      WDigest plaintext creds off, LSA protection (RunAsPPL - needs reboot)
      NTLMv2 only (LmCompatibilityLevel 5), restrict anonymous enumeration
      RDP: Network Level Authentication required
      UAC on, AutoRun/AutoPlay off
      Defender real-time on, PUA protection, signature update, remove exclusions (-ClearDefenderExclusions)
      Print Spooler stopped/disabled (skip with -KeepSpooler on print servers)
.EXAMPLE
    .\05-Harden.ps1                      # preview
    .\05-Harden.ps1 -Apply
    .\05-Harden.ps1 -Apply -KeepSpooler -SkipLsaProtection
    .\05-Harden.ps1 -Rollback
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Rollback,
    [switch]$KeepSpooler,
    [switch]$SkipLsaProtection,
    [switch]$SkipNtlmV2Only,
    [switch]$ClearDefenderExclusions
)

. (Join-Path $PSScriptRoot '..\Config.ps1')
if (-not (Test-CFAdmin)) { Write-CF 'Run as Administrator.' Bad; return }
$hDir = Get-CFDir 'harden'

# --------------------------------------------------------------- rollback
if ($Rollback) {
    $last = Get-ChildItem $hDir -Filter 'rollback-*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $last) { Write-CF 'No rollback file found.' Bad; return }
    $items = Get-Content $last.FullName -Raw | ConvertFrom-Json
    foreach ($i in $items) {
        if ($i.Existed) {
            if (-not (Test-Path $i.Path)) { New-Item -Path $i.Path -Force | Out-Null }
            Set-ItemProperty -Path $i.Path -Name $i.Name -Value $i.OldValue -Type $i.Type
            Write-CF "Restored $($i.Path)\$($i.Name) = $($i.OldValue)" Good
        } else {
            Remove-ItemProperty -Path $i.Path -Name $i.Name -ErrorAction SilentlyContinue
            Write-CF "Removed $($i.Path)\$($i.Name) (did not exist before)" Good
        }
    }
    Write-CF "Registry rolled back from $($last.Name). Services/SMB server config were NOT rolled back - see README." Warn
    return
}

if (-not $Apply) { Write-CF 'DRY RUN - showing what would change. Re-run with -Apply.' Warn }
$undo = New-Object System.Collections.Generic.List[object]

function Set-CFReg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [string]$Why)
    $cur = $null; $existed = $false
    if (Test-Path $Path) {
        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $prop) { $cur = $prop.$Name; $existed = $true }
    }
    if ($existed -and "$cur" -eq "$Value") { Write-CF "OK   $Why" Good; return }
    if (-not $Apply) { Write-CF "WOULD $Why  ($Name : '$cur' -> '$Value')"; return }
    $undo.Add([pscustomobject]@{ Path = $Path; Name = $Name; OldValue = $cur; Existed = $existed; Type = $Type })
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    Write-CF "SET  $Why" Good
}

function Invoke-CFStep {
    param([string]$Why, [scriptblock]$Block)
    if (-not $Apply) { Write-CF "WOULD $Why"; return }
    try { & $Block; Write-CF "DONE $Why" Good } catch { Write-CF "FAIL $Why : $($_.Exception.Message)" Bad }
}

# --------------------------------------------------------------- SMB
Invoke-CFStep 'Disable SMBv1 server' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
Invoke-CFStep 'Require SMB signing (server)' { Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force }
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1 -Why 'Require SMB signing (client)'
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth' 0 -Why 'Block insecure SMB guest logons'
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4 -Why 'Disable SMBv1 client driver'

# --------------------------------------------------------------- name resolution poisoning
Set-CFReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 -Why 'Disable LLMNR'
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' 'Start' 4 -Why 'Disable WPAD auto-proxy service'
Invoke-CFStep 'Disable NetBIOS over TCP/IP on all adapters' {
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = true' |
        ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null }
}

# --------------------------------------------------------------- credentials
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 -Why 'Disable WDigest plaintext credential caching'
if (-not $SkipLsaProtection) {
    Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1 -Why 'Enable LSA protection (reboot required)'
}
if (-not $SkipNtlmV2Only) {
    Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5 -Why 'NTLMv2 only, refuse LM/NTLMv1'
}
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1 -Why 'Do not store LM hashes'
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1 -Why 'Restrict anonymous enumeration'
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1 -Why 'Restrict anonymous SAM enumeration'
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 0 -Why 'Everyone group excludes Anonymous'

# --------------------------------------------------------------- RDP / UAC / AutoRun
Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 -Why 'Require RDP Network Level Authentication'
Set-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1 -Why 'UAC enabled'
Set-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2 -Why 'UAC prompts admins on secure desktop'
Set-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' 0 -Why 'Block remote use of local admin tokens (pass-the-hash)'
Set-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 -Why 'Disable AutoRun on all drives'

# --------------------------------------------------------------- Defender
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    Set-CFReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 0 -Why 'Defender not disabled by policy'
    Set-CFReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 0 -Why 'Defender real-time not disabled by policy'
    Invoke-CFStep 'Defender: real-time, behavior, IOAV, script scanning ON; PUA block' {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false `
            -DisableIOAVProtection $false -DisableScriptScanning $false -PUAProtection Enabled -MAPSReporting Advanced
    }
    Invoke-CFStep 'Defender: update signatures' { Update-MpSignature -ErrorAction Stop }
    $mp = Get-MpPreference
    $ex = @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) | Where-Object { $_ }
    if ($ex) {
        Write-CF "Defender exclusions found: $($ex -join ', ')" Warn
        if ($ClearDefenderExclusions) {
            Invoke-CFStep 'Defender: remove all exclusions' {
                if ($mp.ExclusionPath)      { Remove-MpPreference -ExclusionPath $mp.ExclusionPath }
                if ($mp.ExclusionProcess)   { Remove-MpPreference -ExclusionProcess $mp.ExclusionProcess }
                if ($mp.ExclusionExtension) { Remove-MpPreference -ExclusionExtension $mp.ExclusionExtension }
            }
        } else { Write-CF 'Re-run with -ClearDefenderExclusions to remove them.' Info }
    }
} else { Write-CF 'Defender cmdlets not present on this host.' Warn }

# --------------------------------------------------------------- services
if (-not $KeepSpooler) {
    Invoke-CFStep 'Stop and disable Print Spooler (PrintNightmare)' {
        Stop-Service Spooler -Force -ErrorAction SilentlyContinue
        Set-Service Spooler -StartupType Disabled
    }
}
foreach ($svc in 'RemoteRegistry', 'SNMPTRAP', 'TlntSvr', 'SSDPSRV', 'upnphost') {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s -and $s.StartType -ne 'Disabled') {
        Invoke-CFStep "Disable $svc" { Stop-Service $svc -Force -ErrorAction SilentlyContinue; Set-Service $svc -StartupType Disabled }
    }
}

# --------------------------------------------------------------- save rollback
if ($Apply -and $undo.Count) {
    $f = Join-Path $hDir ("rollback-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $undo | ConvertTo-Json -Depth 3 | Set-Content $f
    Write-CF "Rollback data saved: $f  (undo with -Rollback)" Good
}
if ($Apply -and -not $SkipLsaProtection) { Write-CF 'LSA protection takes effect after a reboot - only reboot if the rules/uptime allow it.' Warn }
Write-CF 'Hardening finished. Re-check scored services now: .\07-ServiceCheck.ps1' Info
