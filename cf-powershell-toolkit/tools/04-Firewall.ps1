<#
.SYNOPSIS
    04 - Firewall: default-deny inbound, allow only scored ports + management from your subnet.
.DESCRIPTION
    DRY RUN BY DEFAULT (shows the plan). Pass -Apply to enforce.
    - Exports the current policy to C:\CF\firewall\ first so -Restore can roll back.
    - Enables all profiles, inbound = Block, outbound = Allow (use -BlockOutbound to tighten).
    - Creates "CF-" rules for $CF_AllowedTcpPorts / $CF_AllowedUdpPorts from Config.ps1.
    - RDP (3389) and WinRM (5985/5986) only from $CF_MgmtSubnets.
    - -DisableOtherInbound turns off every pre-existing inbound Allow rule (the Red team's
      or the image's), leaving only CF- rules. Re-enable individually if something breaks.
    - -Panic: same as -Apply -DisableOtherInbound in one go.
    !! If you are connected over RDP, make sure your IP is inside $CF_MgmtSubnets first.
.EXAMPLE
    .\04-Firewall.ps1                          # preview
    .\04-Firewall.ps1 -Apply
    .\04-Firewall.ps1 -Apply -DisableOtherInbound
    .\04-Firewall.ps1 -Restore                 # roll back to the last export
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$DisableOtherInbound,
    [switch]$BlockOutbound,
    [switch]$Panic,
    [switch]$Restore
)

. (Join-Path $PSScriptRoot '..\Config.ps1')
if (-not (Test-CFAdmin)) { Write-CF 'Run as Administrator.' Bad; return }
$fwDir = Get-CFDir 'firewall'

if ($Restore) {
    $last = Get-ChildItem $fwDir -Filter '*.wfw' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $last) { Write-CF 'No firewall export found to restore.' Bad; return }
    netsh advfirewall import "$($last.FullName)" | Out-Null
    Write-CF "Firewall restored from $($last.FullName)" Good
    return
}

if ($Panic) { $Apply = $true; $DisableOtherInbound = $true }
if (-not $Apply) { Write-CF 'DRY RUN - showing the plan only. Re-run with -Apply.' Warn }

# Show where the current session is coming from so you don't lock yourself out
$rdp = Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction SilentlyContinue
foreach ($c in $rdp) { Write-CF "Active RDP session from $($c.RemoteAddress) - confirm it is inside: $($Global:CF_MgmtSubnets -join ', ')" Warn }

$plan = @()
foreach ($p in $Global:CF_AllowedTcpPorts) { $plan += [pscustomobject]@{ Name = "CF-Allow-TCP-$p"; Proto = 'TCP'; Port = "$p"; Remote = 'Any' } }
foreach ($p in $Global:CF_AllowedUdpPorts) { $plan += [pscustomobject]@{ Name = "CF-Allow-UDP-$p"; Proto = 'UDP'; Port = "$p"; Remote = 'Any' } }
$plan += [pscustomobject]@{ Name = 'CF-Mgmt-RDP';   Proto = 'TCP'; Port = '3389';      Remote = ($Global:CF_MgmtSubnets -join ',') }
$plan += [pscustomobject]@{ Name = 'CF-Mgmt-WinRM'; Proto = 'TCP'; Port = '5985,5986'; Remote = ($Global:CF_MgmtSubnets -join ',') }
$plan | Format-Table -AutoSize | Out-String | Write-Host

if (-not $Apply) {
    if ($DisableOtherInbound) {
        $n = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object DisplayName -notlike 'CF-*').Count
        Write-CF "Would disable $n existing inbound allow rules." Warn
    }
    return
}

# 1. Back up current policy
$export = Join-Path $fwDir ("policy-{0}.wfw" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
netsh advfirewall export "$export" | Out-Null
Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Direction, Action | Export-Csv ($export -replace '\.wfw$', '.csv') -NoTypeInformation
Write-CF "Current policy exported to $export" Good

# 2. Create CF rules (remove old CF rules first so re-runs are clean)
Get-NetFirewallRule -DisplayName 'CF-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
foreach ($r in $plan) {
    $ports  = $r.Port -split ','
    $remote = if ($r.Remote -eq 'Any') { 'Any' } else { $r.Remote -split ',' }
    New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow -Protocol $r.Proto `
        -LocalPort $ports -RemoteAddress $remote -Profile Any | Out-Null
    Write-CF "Rule added: $($r.Name) $($r.Proto)/$($r.Port) from $($r.Remote)" Good
}
# ICMP echo so scoring/ping checks still work
New-NetFirewallRule -DisplayName 'CF-Allow-ICMPv4' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null

# 3. Optionally disable everything else that allows inbound
if ($DisableOtherInbound) {
    $others = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object DisplayName -notlike 'CF-*'
    $others | Disable-NetFirewallRule
    Write-CF "Disabled $(@($others).Count) other inbound allow rules (see $($export -replace '\.wfw$', '.csv'))" Warn
}

# 4. Turn it on, default-deny inbound, log drops
$outbound = if ($BlockOutbound) { 'Block' } else { 'Allow' }
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction $outbound `
    -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384 `
    -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
Write-CF "Firewall ON for all profiles. Inbound=Block, Outbound=$outbound. Drops logged to pfirewall.log" Good

if ($BlockOutbound) {
    Write-CF 'Outbound is blocked - add CF- outbound rules for DNS/updates/AD as needed or services may fail!' Warn
}
Write-CF 'Rollback anytime with: .\04-Firewall.ps1 -Restore' Info
