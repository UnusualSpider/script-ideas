<#
.SYNOPSIS
    08 - Backup and restore the things the Red team likes to break.
.DESCRIPTION
    -Backup (default action) saves to C:\CF\backup\<time>\ :
        Web roots (C:\inetpub\wwwroot + -Paths you add), IIS config (appcmd backup),
        on a DC: all GPOs, AD users/groups/OU export, DNS zones,
        hosts file, scheduled-task XML, firewall policy, any extra -Paths.
    -RestoreWeb   : copy the newest web-root backup back over the live site
    -RestoreIIS   : restore the newest IIS config backup
    -RestoreGPO   : restore every GPO from the newest backup
    -RestoreHosts : restore the hosts file
    -ListDeletedAD: show deleted AD objects (needs AD Recycle Bin)
    -RestoreADObject <name> : undelete an AD object by name (needs AD Recycle Bin)
    -EnableADRecycleBin     : turn on AD Recycle Bin (ONE-WAY change - check the rules first)
.EXAMPLE
    .\08-BackupRestore.ps1
    .\08-BackupRestore.ps1 -Paths 'C:\SCADA\config','D:\www'
    .\08-BackupRestore.ps1 -RestoreWeb
    .\08-BackupRestore.ps1 -RestoreADObject jsmith
#>
[CmdletBinding()]
param(
    [string[]]$Paths = @(),
    [switch]$RestoreWeb,
    [switch]$RestoreIIS,
    [switch]$RestoreGPO,
    [switch]$RestoreHosts,
    [switch]$ListDeletedAD,
    [string]$RestoreADObject,
    [switch]$EnableADRecycleBin
)

. (Join-Path $PSScriptRoot '..\Config.ps1')
if (-not (Test-CFAdmin)) { Write-CF 'Run as Administrator.' Bad; return }
$root   = Get-CFDir 'backup'
$isDC   = Test-CFIsDC
$appcmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
$webRoots = @('C:\inetpub\wwwroot') + $Paths | Where-Object { Test-Path $_ }

function Get-CFLatestBackup {
    Get-ChildItem $root -Directory | Sort-Object Name -Descending | Select-Object -First 1
}
function ConvertTo-CFSafeName { param([string]$p) ($p -replace '[:\\/]', '_').Trim('_') }

# ------------------------------------------------------------------ AD helpers
if ($isDC) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue }

if ($EnableADRecycleBin) {
    if (-not $isDC) { Write-CF 'Run this on a domain controller.' Bad; return }
    $forest = (Get-ADForest).Name
    Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forest -Confirm:$false
    Write-CF 'AD Recycle Bin enabled.' Good
    return
}
if ($ListDeletedAD) {
    Get-ADObject -Filter 'isDeleted -eq $true -and Name -ne "Deleted Objects"' -IncludeDeletedObjects -Properties whenChanged, samAccountName |
        Select-Object Name, samAccountName, ObjectClass, whenChanged | Format-Table -AutoSize
    return
}
if ($RestoreADObject) {
    $o = Get-ADObject -Filter "samAccountName -eq '$RestoreADObject' -and isDeleted -eq `$true" -IncludeDeletedObjects
    if (-not $o) { Write-CF "No deleted object with samAccountName $RestoreADObject" Bad; return }
    $o | Restore-ADObject
    Write-CF "Restored AD object $RestoreADObject" Good
    return
}

# ------------------------------------------------------------------ restores
if ($RestoreWeb -or $RestoreIIS -or $RestoreGPO -or $RestoreHosts) {
    $b = Get-CFLatestBackup
    if (-not $b) { Write-CF 'No backup found.' Bad; return }
    Write-CF "Restoring from $($b.FullName)" Warn

    if ($RestoreWeb) {
        $map = Join-Path $b.FullName 'files\map.csv'
        if (Test-Path $map) {
            foreach ($m in Import-Csv $map) {
                $src = Join-Path $b.FullName "files\$($m.Folder)"
                robocopy $src $m.Source /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
                Write-CF "Restored $($m.Source) (mirror - files added since backup were removed)" Good
            }
        } else { Write-CF 'No file backups in that set.' Warn }
    }
    if ($RestoreIIS -and (Test-Path $appcmd)) {
        $name = Get-Content (Join-Path $b.FullName 'iis_backup_name.txt') -ErrorAction SilentlyContinue
        if ($name) { & $appcmd restore backup $name | Out-Null; Write-CF "IIS config restored ($name)" Good; iisreset /restart | Out-Null }
        else { Write-CF 'No IIS backup name recorded.' Warn }
    }
    if ($RestoreGPO -and $isDC) {
        $gdir = Join-Path $b.FullName 'gpo'
        if (Test-Path $gdir) { Restore-GPO -All -Domain (Get-ADDomain).DNSRoot -Path $gdir | Out-Null; Write-CF 'All GPOs restored' Good }
    }
    if ($RestoreHosts) {
        Copy-Item (Join-Path $b.FullName 'hosts') "$env:windir\System32\drivers\etc\hosts" -Force
        Write-CF 'hosts file restored' Good
    }
    return
}

# ------------------------------------------------------------------ backup
$dir = Join-Path $root (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Write-CF "Backing up to $dir"

# Files / web roots
$fdir = Join-Path $dir 'files'
New-Item -ItemType Directory -Path $fdir -Force | Out-Null
$map = foreach ($p in $webRoots) {
    $safe = ConvertTo-CFSafeName $p
    robocopy $p (Join-Path $fdir $safe) /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
    Write-CF "Copied $p" Good
    [pscustomobject]@{ Source = $p; Folder = $safe }
}
if ($map) { $map | Export-Csv (Join-Path $fdir 'map.csv') -NoTypeInformation }

# IIS config
if (Test-Path $appcmd) {
    $name = "CF-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    & $appcmd add backup $name | Out-Null
    Set-Content (Join-Path $dir 'iis_backup_name.txt') $name
    Copy-Item "$env:windir\System32\inetsrv\config\applicationHost.config" $dir -ErrorAction SilentlyContinue
    Write-CF "IIS config backed up as '$name'" Good
}

# Domain controller items
if ($isDC) {
    $gdir = Join-Path $dir 'gpo'; New-Item -ItemType Directory $gdir -Force | Out-Null
    try { Backup-GPO -All -Path $gdir | Out-Null; Write-CF 'All GPOs backed up' Good } catch { Write-CF "GPO backup failed: $($_.Exception.Message)" Warn }

    Get-ADUser -Filter * -Properties * | Select-Object SamAccountName, Name, Enabled, DistinguishedName, MemberOf, Description |
        ForEach-Object { $_.MemberOf = $_.MemberOf -join ';'; $_ } | Export-Csv (Join-Path $dir 'ad_users.csv') -NoTypeInformation
    Get-ADGroup -Filter * | ForEach-Object {
        [pscustomobject]@{ Group = $_.Name; Members = ((Get-ADGroupMember $_ -ErrorAction SilentlyContinue).SamAccountName -join ';') }
    } | Export-Csv (Join-Path $dir 'ad_groups.csv') -NoTypeInformation
    Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName | Export-Csv (Join-Path $dir 'ad_ous.csv') -NoTypeInformation
    Write-CF 'AD users/groups/OUs exported' Good

    $rb = Get-ADOptionalFeature -Filter 'Name -like "Recycle Bin Feature"'
    if (-not $rb.EnabledScopes) { Write-CF 'AD Recycle Bin is OFF - deleted users cannot be undeleted. See -EnableADRecycleBin.' Warn }
}

# DNS zones
if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
    $ddir = Join-Path $dir 'dns'; New-Item -ItemType Directory $ddir -Force | Out-Null
    foreach ($z in Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' }) {
        $fname = "cf_$($z.ZoneName).dns"
        try {
            Export-DnsServerZone -Name $z.ZoneName -FileName $fname -ErrorAction Stop
            Move-Item "$env:windir\System32\dns\$fname" $ddir -Force
            Get-DnsServerResourceRecord -ZoneName $z.ZoneName | Select-Object HostName, RecordType, TimeToLive,
                @{n='Data';e={ ($_.RecordData.PSObject.Properties | Where-Object { $_.Value -and $_.Name -notlike 'Cim*' } | ForEach-Object { "$($_.Value)" }) -join ' ' }} |
                Export-Csv (Join-Path $ddir "$($z.ZoneName).csv") -NoTypeInformation
            Write-CF "DNS zone exported: $($z.ZoneName)" Good
        } catch { Write-CF "DNS zone $($z.ZoneName) failed: $($_.Exception.Message)" Warn }
    }
}

# Misc
Copy-Item "$env:windir\System32\drivers\etc\hosts" (Join-Path $dir 'hosts')
netsh advfirewall export (Join-Path $dir 'firewall.wfw') | Out-Null
$tdir = Join-Path $dir 'tasks'; New-Item -ItemType Directory $tdir -Force | Out-Null
Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft\*' | ForEach-Object {
    Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Set-Content (Join-Path $tdir "$(ConvertTo-CFSafeName $_.TaskName).xml")
}

$size = '{0:N1} MB' -f ((Get-ChildItem $dir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB)
Write-CF "Backup complete ($size): $dir" Good
Write-CF 'Copy C:\CF\backup to another machine or USB - backups on the same box can be wiped too.' Warn
