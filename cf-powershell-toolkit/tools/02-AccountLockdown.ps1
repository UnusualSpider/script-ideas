<#
.SYNOPSIS
    02 - Account lockdown: rotate passwords, disable Guest, prune admin groups, set policy.
.DESCRIPTION
    DRY RUN BY DEFAULT. Nothing changes unless you pass -Apply.
    - Skips every account in $CF_ExcludedAccounts (scoring/service accounts).
    - On a domain controller it works on AD users; otherwise on local users.
    - New passwords are written to C:\CF\secrets\passwords-<host>-<time>.csv.
      Move that file somewhere safe (USB / password manager) and delete it from the box.
.PARAMETER Apply
    Actually make changes.
.PARAMETER SkipPasswords
    Do everything except password rotation.
.PARAMETER RemoveUnapprovedAdmins
    Remove members of privileged groups that are not in $CF_ApprovedAdmins.
    Without this switch they are only reported.
.PARAMETER Users
    Rotate only these accounts (default: all enabled, non-excluded users).
.EXAMPLE
    .\02-AccountLockdown.ps1                 # preview
    .\02-AccountLockdown.ps1 -Apply          # do it
    .\02-AccountLockdown.ps1 -Apply -Users bob,alice
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$SkipPasswords,
    [switch]$RemoveUnapprovedAdmins,
    [string[]]$Users,
    [int]$PasswordLength = 16
)

. (Join-Path $PSScriptRoot '..\Config.ps1')
if (-not (Test-CFAdmin)) { Write-CF 'Run as Administrator.' Bad; return }
if (-not $Apply) { Write-CF 'DRY RUN - no changes will be made. Re-run with -Apply.' Warn }

$isDC = Test-CFIsDC
if ($isDC) { Import-Module ActiveDirectory -ErrorAction Stop; Write-CF 'Domain controller detected - operating on AD accounts.' }

function New-CFPassword {
    param([int]$Length = 16)
    # No ambiguous characters (0/O, 1/l/I) and no quotes/backticks that break scripts or typing
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray()
    $lower = 'abcdefghijkmnpqrstuvwxyz'.ToCharArray()
    $digit = '23456789'.ToCharArray()
    $sym   = '!@#$%^*-_=+?'.ToCharArray()
    $all   = $upper + $lower + $digit + $sym
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $pick  = {
        param($set)
        $b = New-Object byte[] 4; $rng.GetBytes($b)
        $set[[BitConverter]::ToUInt32($b, 0) % $set.Length]
    }
    $chars = @( (& $pick $upper), (& $pick $lower), (& $pick $digit), (& $pick $sym) )
    while ($chars.Count -lt $Length) { $chars += (& $pick $all) }
    # shuffle
    ($chars | Sort-Object { $b = New-Object byte[] 4; $rng.GetBytes($b); [BitConverter]::ToUInt32($b,0) }) -join ''
}

# ---------------------------------------------------------------- password rotation
$results = @()
if (-not $SkipPasswords) {
    if ($isDC) {
        $targets = Get-ADUser -Filter 'Enabled -eq $true' | Where-Object { -not (Test-CFExcluded $_.SamAccountName) }
        if ($Users) { $targets = $targets | Where-Object { $Users -contains $_.SamAccountName } }
        foreach ($u in $targets) {
            $pw = New-CFPassword -Length $PasswordLength
            if ($Apply) {
                try {
                    Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
                    $results += [pscustomobject]@{ Account = $u.SamAccountName; Password = $pw; Status = 'Changed' }
                    Write-CF "Password rotated: $($u.SamAccountName)" Good
                } catch {
                    $results += [pscustomobject]@{ Account = $u.SamAccountName; Password = ''; Status = "FAILED: $($_.Exception.Message)" }
                    Write-CF "FAILED $($u.SamAccountName): $($_.Exception.Message)" Bad
                }
            } else { Write-CF "Would rotate: $($u.SamAccountName)" }
        }
    } else {
        $targets = Get-LocalUser | Where-Object { $_.Enabled -and -not (Test-CFExcluded $_.Name) }
        if ($Users) { $targets = $targets | Where-Object { $Users -contains $_.Name } }
        foreach ($u in $targets) {
            $pw = New-CFPassword -Length $PasswordLength
            if ($Apply) {
                try {
                    Set-LocalUser -Name $u.Name -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
                    $results += [pscustomobject]@{ Account = $u.Name; Password = $pw; Status = 'Changed' }
                    Write-CF "Password rotated: $($u.Name)" Good
                } catch {
                    $results += [pscustomobject]@{ Account = $u.Name; Password = ''; Status = "FAILED: $($_.Exception.Message)" }
                    Write-CF "FAILED $($u.Name): $($_.Exception.Message)" Bad
                }
            } else { Write-CF "Would rotate: $($u.Name)" }
        }
    }
    if ($Apply -and $results) {
        $f = Join-Path (Get-CFDir 'secrets') ("passwords-{0}-{1}.csv" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $results | Export-Csv $f -NoTypeInformation
        Write-CF "New passwords saved to $f  <-- copy off the box, then delete it" Warn
    }
}

# ---------------------------------------------------------------- Guest / default accounts
foreach ($name in 'Guest', 'DefaultAccount') {
    if ($isDC) {
        $a = Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue
        if ($a -and $a.Enabled) { if ($Apply) { Disable-ADAccount $a; Write-CF "Disabled $name" Good } else { Write-CF "Would disable $name" } }
    } else {
        $a = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($a -and $a.Enabled) { if ($Apply) { Disable-LocalUser -Name $name; Write-CF "Disabled $name" Good } else { Write-CF "Would disable $name" } }
    }
}

# ---------------------------------------------------------------- privileged group review
$approved = $Global:CF_ApprovedAdmins + $Global:CF_ExcludedAccounts
if ($isDC) {
    foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'DnsAdmins') {
        $members = Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue
        foreach ($m in $members) {
            if ($approved -contains $m.SamAccountName -or $m.objectClass -eq 'group') { continue }
            if ($RemoveUnapprovedAdmins -and $Apply) {
                Remove-ADGroupMember -Identity $g -Members $m -Confirm:$false
                Write-CF "Removed $($m.SamAccountName) from $g" Good
            } else {
                Write-CF "UNAPPROVED member of ${g}: $($m.SamAccountName)" Warn
            }
        }
    }
} else {
    foreach ($g in 'Administrators', 'Remote Desktop Users', 'Remote Management Users', 'Backup Operators') {
        $members = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        foreach ($m in $members) {
            $short = ($m.Name -split '\\')[-1]
            if ($approved -contains $short -or $short -in 'Domain Admins', 'Enterprise Admins') { continue }
            if ($RemoveUnapprovedAdmins -and $Apply) {
                Remove-LocalGroupMember -Group $g -Member $m.Name
                Write-CF "Removed $($m.Name) from $g" Good
            } else {
                Write-CF "UNAPPROVED member of ${g}: $($m.Name)" Warn
            }
        }
    }
}

# ---------------------------------------------------------------- password & lockout policy
if ($isDC) {
    $domain = (Get-ADDomain).DistinguishedName
    if ($Apply) {
        Set-ADDefaultDomainPasswordPolicy -Identity $domain -MinPasswordLength 12 -ComplexityEnabled $true `
            -LockoutThreshold 10 -LockoutDuration '00:15:00' -LockoutObservationWindow '00:15:00' -ReversibleEncryptionEnabled $false
        Write-CF 'Domain password/lockout policy set (min 12, complex, lockout 10/15min)' Good
    } else { Write-CF 'Would set domain password/lockout policy' }

    # Kerberoast / AS-REP roast exposure report
    Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | ForEach-Object { Write-CF "AS-REP roastable (no preauth): $($_.SamAccountName)" Warn }
    Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName |
        Where-Object SamAccountName -ne 'krbtgt' | ForEach-Object { Write-CF "Has SPN (kerberoastable): $($_.SamAccountName)" Warn }
} else {
    if ($Apply) {
        net accounts /minpwlen:12 /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
        Write-CF 'Local password/lockout policy set' Good
    } else { Write-CF 'Would set local password/lockout policy' }
}

Write-CF 'Account lockdown finished.' Good
