<#
    CyberForce Toolkit - shared configuration
    EDIT THIS FILE FIRST once you see your environment and the competition rules.
    Every tool dot-sources this file.
#>

# Where all output (baselines, reports, backups, password lists) is written.
$Global:CF_OutputRoot = 'C:\CF'

# Accounts the scripts must NEVER touch (scoring / service / black-team accounts).
# The rules packet usually names these. Matching is case-insensitive, exact name.
$Global:CF_ExcludedAccounts = @(
    'krbtgt'
    # 'scoring'
    # 'blackteam'
    # 'svc_scada'
)

# Accounts that are SUPPOSED to be in privileged groups. Anyone else gets flagged/removed.
$Global:CF_ApprovedAdmins = @(
    'Administrator'
    # 'teamadmin'
)

# Your team's management subnet(s) - RDP/WinRM will only be allowed from here.
$Global:CF_MgmtSubnets = @(
    '10.0.0.0/24'
)

# Inbound TCP/UDP ports for scored services on THIS box. Adjust per host role.
# Example roles - uncomment / edit the one that fits the machine you are on.
$Global:CF_AllowedTcpPorts = @(
    80, 443          # web
    # 53             # DNS
    # 88, 135, 389, 445, 464, 636, 3268, 3269   # domain controller
    # '49152-65535'  # DC dynamic RPC (use with care) - ranges MUST be quoted strings
)
$Global:CF_AllowedUdpPorts = @(
    # 53, 88, 123, 389, 464
)

# Scored services to health-check. Type = Service | Http | Tcp
$Global:CF_ScoredChecks = @(
    @{ Name = 'IIS';      Type = 'Service'; Target = 'W3SVC' }
    @{ Name = 'Web page'; Type = 'Http';    Target = 'http://localhost/' }
    # @{ Name = 'DNS';    Type = 'Service'; Target = 'DNS' }
    # @{ Name = 'AD DS';  Type = 'Service'; Target = 'NTDS' }
    # @{ Name = 'HMI';    Type = 'Tcp';     Target = '10.0.0.50:502' }
)

# Health-check loop interval (seconds)
$Global:CF_CheckInterval = 60

# ---- helpers used by every tool ----
function Write-CF {
    param([string]$Msg, [ValidateSet('Info','Good','Warn','Bad')][string]$Level = 'Info')
    $color = @{ Info = 'Cyan'; Good = 'Green'; Warn = 'Yellow'; Bad = 'Red' }[$Level]
    $line  = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.ToUpper(), $Msg
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path (Join-Path $Global:CF_OutputRoot 'toolkit.log') -Value $line -ErrorAction Stop } catch {}
}

function Get-CFDir {
    param([string]$Sub)
    $p = Join-Path $Global:CF_OutputRoot $Sub
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    return $p
}

function Test-CFAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CFIsDC {
    try { (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4 } catch { $false }
}

function Test-CFExcluded {
    param([string]$Name)
    $Global:CF_ExcludedAccounts -contains $Name
}

if (-not (Test-Path $Global:CF_OutputRoot)) { New-Item -ItemType Directory -Path $Global:CF_OutputRoot -Force | Out-Null }
