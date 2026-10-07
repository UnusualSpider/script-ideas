<#
.SYNOPSIS
    07 - Scored-service health check with optional auto-restart.
.DESCRIPTION
    Checks every entry in $CF_ScoredChecks (Config.ps1):
      Service : Windows service is Running (restarts it with -AutoFix)
      Http    : URL returns HTTP 2xx/3xx
      Tcp     : host:port accepts a connection
    Also flags if the web root's default page changed (defacement) when -WebRoot is given.
.EXAMPLE
    .\07-ServiceCheck.ps1                      # check once
    .\07-ServiceCheck.ps1 -Loop -AutoFix       # watch forever, restart what dies
    .\07-ServiceCheck.ps1 -Loop -WebRoot C:\inetpub\wwwroot
#>
[CmdletBinding()]
param(
    [switch]$Loop,
    [switch]$AutoFix,
    [string]$WebRoot
)

. (Join-Path $PSScriptRoot '..\Config.ps1')

# Hash the web root once so we can detect defacement
$webHashes = @{}
if ($WebRoot -and (Test-Path $WebRoot)) {
    Get-ChildItem $WebRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $webHashes[$_.FullName] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
    Write-CF "Hashed $($webHashes.Count) files under $WebRoot for defacement detection"
}

function Test-CFCheck {
    param($c)
    switch ($c.Type) {
        'Service' {
            $s = Get-Service -Name $c.Target -ErrorAction SilentlyContinue
            if (-not $s) { return @{ Ok = $false; Info = 'service not found' } }
            if ($s.Status -eq 'Running') { return @{ Ok = $true; Info = 'Running' } }
            if ($AutoFix) {
                try {
                    if ($s.StartType -eq 'Disabled') { Set-Service $c.Target -StartupType Automatic }
                    Start-Service $c.Target -ErrorAction Stop
                    return @{ Ok = $true; Info = "was $($s.Status) - RESTARTED" }
                } catch { return @{ Ok = $false; Info = "restart failed: $($_.Exception.Message)" } }
            }
            return @{ Ok = $false; Info = $s.Status }
        }
        'Http' {
            try {
                $r = Invoke-WebRequest -Uri $c.Target -UseBasicParsing -TimeoutSec 8 -MaximumRedirection 3 -ErrorAction Stop
                return @{ Ok = ($r.StatusCode -lt 400); Info = "HTTP $($r.StatusCode), $($r.RawContentLength) bytes" }
            } catch {
                $code = $_.Exception.Response.StatusCode.value__
                return @{ Ok = $false; Info = if ($code) { "HTTP $code" } else { $_.Exception.Message } }
            }
        }
        'Tcp' {
            $hostName, $port = $c.Target -split ':'
            $client = New-Object System.Net.Sockets.TcpClient
            try {
                $ok = $client.ConnectAsync($hostName, [int]$port).Wait(4000)
                return @{ Ok = ($ok -and $client.Connected); Info = if ($ok) { 'open' } else { 'timeout' } }
            } catch { return @{ Ok = $false; Info = $_.Exception.InnerException.Message } }
            finally { $client.Dispose() }
        }
    }
}

$history = Join-Path (Get-CFDir 'reports') "uptime-$env:COMPUTERNAME.csv"

do {
    Write-Host ''
    Write-CF "---- Service check $(Get-Date -Format 'HH:mm:ss') ----"
    $down = 0
    foreach ($c in $Global:CF_ScoredChecks) {
        $r = Test-CFCheck $c
        $lvl = if ($r.Ok) { if ($r.Info -like '*RESTARTED*') { 'Warn' } else { 'Good' } } else { 'Bad' }
        if (-not $r.Ok) { $down++ }
        Write-CF ("{0,-14} {1,-8} {2}" -f $c.Name, $(if ($r.Ok) { 'UP' } else { 'DOWN' }), $r.Info) $lvl
        [pscustomobject]@{ Time = Get-Date -Format 's'; Check = $c.Name; Up = $r.Ok; Info = $r.Info } |
            Export-Csv $history -Append -NoTypeInformation
    }

    if ($webHashes.Count) {
        foreach ($f in $webHashes.Keys) {
            if (-not (Test-Path $f)) { Write-CF "WEB FILE DELETED: $f" Bad; $down++; continue }
            if ((Get-FileHash $f -Algorithm SHA256).Hash -ne $webHashes[$f]) { Write-CF "WEB FILE CHANGED (defacement?): $f" Bad; $down++ }
        }
        Get-ChildItem $WebRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object { -not $webHashes.ContainsKey($_.FullName) } |
            ForEach-Object { Write-CF "NEW FILE in web root (webshell?): $($_.FullName)" Bad; $down++ }
    }

    if ($down -gt 0) { [console]::Beep(880, 300) }
    if ($Loop) { Start-Sleep -Seconds $Global:CF_CheckInterval }
} while ($Loop)
