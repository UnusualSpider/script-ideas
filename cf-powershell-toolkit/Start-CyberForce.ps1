<#
.SYNOPSIS
    CyberForce Toolkit - menu launcher.
.DESCRIPTION
    Run from an elevated PowerShell:
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\Start-CyberForce.ps1
#>
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'Config.ps1')
$T = Join-Path $PSScriptRoot 'tools'

if (-not (Test-CFAdmin)) {
    Write-Host 'Not elevated - right-click PowerShell > Run as Administrator.' -ForegroundColor Red
    return
}

function Invoke-CFTool { param([string]$Script, [hashtable]$ToolArgs = @{})
    & (Join-Path $T $Script) @ToolArgs
    Write-Host ''
    Read-Host 'Press Enter to return to the menu' | Out-Null
}

function Confirm-CF { param([string]$Msg)
    (Read-Host "$Msg [y/N]") -match '^(y|yes)$'
}

while ($true) {
    Clear-Host
    $role = if (Test-CFIsDC) { 'Domain Controller' } else { 'Member/Standalone' }
    Write-Host '=================================================' -ForegroundColor Cyan
    Write-Host '   CyberForce Blue Team Toolkit' -ForegroundColor Cyan
    Write-Host "   Host: $env:COMPUTERNAME  ($role)" -ForegroundColor Cyan
    Write-Host "   Output: $($Global:CF_OutputRoot)" -ForegroundColor Cyan
    Write-Host '=================================================' -ForegroundColor Cyan
    Write-Host ' 0) FIRST 10 MINUTES  (baseline + backup + logging + previews)' -ForegroundColor Yellow
    Write-Host ' 1) Baseline inventory'
    Write-Host ' 2) Account lockdown  (preview / apply)'
    Write-Host ' 3) Persistence hunt'
    Write-Host ' 4) Firewall          (preview / apply / restore)'
    Write-Host ' 5) Harden            (preview / apply / rollback)'
    Write-Host ' 6) Logging           (enable / query last hour)'
    Write-Host ' 7) Service check     (once / watch with auto-restart)'
    Write-Host ' 8) Backup / restore'
    Write-Host ' C) Edit Config.ps1'
    Write-Host ' Q) Quit'
    $c = Read-Host 'Choose'

    switch ($c.ToUpper()) {
        '0' {
            & (Join-Path $T '01-Baseline.ps1')
            & (Join-Path $T '08-BackupRestore.ps1')
            & (Join-Path $T '06-Logging.ps1') -Enable
            & (Join-Path $T '02-AccountLockdown.ps1')
            & (Join-Path $T '04-Firewall.ps1')
            & (Join-Path $T '05-Harden.ps1')
            & (Join-Path $T '07-ServiceCheck.ps1')
            Write-Host "`nReview the previews above, fix Config.ps1 if needed, then apply 2/4/5 from the menu." -ForegroundColor Yellow
            Read-Host 'Press Enter' | Out-Null
        }
        '1' { Invoke-CFTool '01-Baseline.ps1' }
        '2' {
            & (Join-Path $T '02-AccountLockdown.ps1')
            if (Confirm-CF 'Apply these account changes?') {
                $rm = Confirm-CF 'Also REMOVE unapproved admin group members?'
                Invoke-CFTool '02-AccountLockdown.ps1' @{ Apply = $true; RemoveUnapprovedAdmins = $rm }
            }
        }
        '3' { Invoke-CFTool '03-HuntPersistence.ps1' }
        '4' {
            $m = Read-Host 'Firewall: (P)review, (A)pply, apply + disable (O)ther inbound rules, (R)estore'
            switch ($m.ToUpper()) {
                'A' { Invoke-CFTool '04-Firewall.ps1' @{ Apply = $true } }
                'O' { if (Confirm-CF 'Disable ALL non-CF inbound allow rules?') { Invoke-CFTool '04-Firewall.ps1' @{ Apply = $true; DisableOtherInbound = $true } } }
                'R' { Invoke-CFTool '04-Firewall.ps1' @{ Restore = $true } }
                default { Invoke-CFTool '04-Firewall.ps1' }
            }
        }
        '5' {
            $m = Read-Host 'Harden: (P)review, (A)pply, (R)ollback'
            switch ($m.ToUpper()) {
                'A' {
                    $spool = Confirm-CF 'Is this a print server (keep Print Spooler)?'
                    Invoke-CFTool '05-Harden.ps1' @{ Apply = $true; KeepSpooler = $spool }
                }
                'R' { Invoke-CFTool '05-Harden.ps1' @{ Rollback = $true } }
                default { Invoke-CFTool '05-Harden.ps1' }
            }
        }
        '6' {
            $m = Read-Host 'Logging: (E)nable, (Q)uery'
            if ($m -match '^[eE]') { Invoke-CFTool '06-Logging.ps1' @{ Enable = $true } }
            else {
                $h = Read-Host 'How many hours back? [1]'; if (-not $h) { $h = 1 }
                Invoke-CFTool '06-Logging.ps1' @{ Hours = [double]$h; Export = $true }
            }
        }
        '7' {
            $m = Read-Host 'Service check: (O)nce, (W)atch with auto-restart (Ctrl+C to stop)'
            if ($m -match '^[wW]') {
                $wr = Read-Host 'Web root to watch for defacement (blank = skip)'
                $a = @{ Loop = $true; AutoFix = $true }; if ($wr) { $a.WebRoot = $wr }
                Invoke-CFTool '07-ServiceCheck.ps1' $a
            } else { Invoke-CFTool '07-ServiceCheck.ps1' }
        }
        '8' {
            $m = Read-Host 'Backup: (B)ackup now, restore (W)eb, restore (I)IS, restore (G)POs, restore (H)osts, (D)eleted AD objects'
            switch ($m.ToUpper()) {
                'W' { Invoke-CFTool '08-BackupRestore.ps1' @{ RestoreWeb = $true } }
                'I' { Invoke-CFTool '08-BackupRestore.ps1' @{ RestoreIIS = $true } }
                'G' { Invoke-CFTool '08-BackupRestore.ps1' @{ RestoreGPO = $true } }
                'H' { Invoke-CFTool '08-BackupRestore.ps1' @{ RestoreHosts = $true } }
                'D' { Invoke-CFTool '08-BackupRestore.ps1' @{ ListDeletedAD = $true } }
                default { Invoke-CFTool '08-BackupRestore.ps1' }
            }
        }
        'C' { Start-Process notepad (Join-Path $PSScriptRoot 'Config.ps1') -Wait; . (Join-Path $PSScriptRoot 'Config.ps1') }
        'Q' { return }
    }
}
