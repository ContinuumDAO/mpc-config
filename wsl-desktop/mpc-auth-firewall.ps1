#Requires -Version 5.1
<#
.SYNOPSIS
  Windows host firewall for an MPA Wallet node on Docker Desktop.

  Docker accepts the published ports on Windows before the packet enters the
  WSL VM, where every internet address usually looks like the Docker gateway.
  Rules therefore live in Windows Firewall, which still sees the real source.

  Per-address connection caps need a kernel driver Windows Firewall does not
  provide. This script allows the node TCP ports, limits 18081 to the scanner
  egress addresses from the shared plan when that can be expressed, and blocks
  SSH sources that fail login six times in ten minutes for one hour.

  A Block rule overrides every Allow, including the scanner. This script never
  adds a world block on 18081. If Docker Desktop already has an application
  allow for that port, other sources can still connect; the named allow records
  the intended scanner egress.
#>
[CmdletBinding()]
param(
  [ValidateSet('apply', 'install', 'remove')]
  [string]$Action = 'apply',
  [string]$Distro = '',
  [string]$Repo = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskLogon = 'ContinuumNodeMpcAuthFirewall'
$TaskPoll = 'ContinuumNodeMpcAuthFirewallPoll'

function Get-ContinuumDir {
  Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Continuum'
}

function Read-PlanText {
  param([string]$Text)
  $caps = @()
  $scanSources = @()
  $scanPort = 0
  $scanDrop = $false
  $sshPort = 22
  $ignore = @()
  foreach ($raw in ($Text -split "`n")) {
    $line = $raw.Trim()
    if (-not $line) { continue }
    if ($line.StartsWith('CAP=')) {
      $parts = $line.Substring(4).Split(' ')
      $caps += [int]$parts[0]
    } elseif ($line.StartsWith('SCANCAP=')) {
      $parts = $line.Substring(8).Split(' ')
      $scanPort = [int]$parts[0]
      $scanSources += $parts[4]
    } elseif ($line.StartsWith('SCANDROP=')) {
      $scanDrop = $true
      $scanPort = [int]$line.Substring(9)
    } elseif ($line.StartsWith('SSH=')) {
      $sshPort = [int]$line.Substring(4).Split(' ')[0]
    } elseif ($line.StartsWith('IGNORE=')) {
      $ignore += $line.Substring(7)
    }
  }
  [pscustomobject]@{
    Caps         = @($caps | Select-Object -Unique)
    ScanPort     = $scanPort
    ScanDrop     = $scanDrop
    ScanSources  = @($scanSources | Select-Object -Unique)
    SshPort      = $sshPort
    Ignore       = @($ignore)
  }
}

function Get-PlanFromWsl {
  $dir = Get-ContinuumDir
  $distroFile = Join-Path $dir 'distro.txt'
  $repoFile = Join-Path $dir 'repo.txt'
  if (-not $Distro -and (Test-Path -LiteralPath $distroFile)) {
    $Distro = (Get-Content -LiteralPath $distroFile -Raw).Trim()
  }
  if (-not $Repo -and (Test-Path -LiteralPath $repoFile)) {
    $Repo = (Get-Content -LiteralPath $repoFile -Raw).Trim()
  }
  if (-not $Distro -or -not $Repo) {
    throw "Windows firewall plan is missing distro or repo (expected $distroFile and $repoFile)"
  }
  $bash = "if [ -x '$Repo/.venv-provision/bin/python3' ]; then export PATH='$Repo/.venv-provision/bin:'`$PATH; fi; if [ -d '$Repo/.provision-py' ]; then export PYTHONPATH='$Repo/.provision-py'; fi; bash '$Repo/scripts/lib/mpc-auth-ddos-guard.sh' --config '$Repo/configs.yaml' --print-plan"
  $out = & wsl.exe -d $Distro -- bash -lc $bash
  if ($LASTEXITCODE -ne 0) {
    throw "failed to read the connection-guard plan from WSL ($Distro)"
  }
  ($out | Out-String)
}

function Remove-NamedRules {
  param([string]$Prefix)
  $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$Prefix*" })
  foreach ($rule in $rules) {
    Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
  }
}

function Add-AllowPort {
  param(
    [int]$Port,
    [string[]]$RemoteAddress
  )
  $name = "ContinuumMPC-allow-$Port"
  $params = @{
    Name        = $name
    DisplayName = $name
    Direction   = 'Inbound'
    Action      = 'Allow'
    Protocol    = 'TCP'
    LocalPort   = "$Port"
    Profile     = 'Any'
    Description = 'MPA Wallet host allow. Windows Firewall cannot cap connections per address.'
  }
  if ($RemoteAddress -and $RemoteAddress.Count -gt 0) {
    $params.RemoteAddress = $RemoteAddress
    $params.Description = "MPA Wallet scanner/relayer allow for $($RemoteAddress -join ', '). A broader Docker Desktop application allow can still admit other sources; a world Block is not installed because Block overrides Allow."
  }
  New-NetFirewallRule @params | Out-Null
}

function Test-PrivateOrIgnore {
  param(
    [string]$Ip,
    [string[]]$Ignore
  )
  if ($Ip -match '^(127\.|10\.|192\.168\.|169\.254\.)') { return $true }
  if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
  foreach ($item in $Ignore) {
    if (-not $item) { continue }
    if ($item -eq $Ip) { return $true }
    if ($item -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
      $base = [System.Net.IPAddress]::Parse($Matches[1]).GetAddressBytes()
      $addr = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
      [array]::Reverse($base)
      [array]::Reverse($addr)
      $baseInt = [BitConverter]::ToUInt32($base, 0)
      $addrInt = [BitConverter]::ToUInt32($addr, 0)
      $bits = [int]$Matches[2]
      if ($bits -le 0) { return $true }
      $mask = [uint32](([uint64]0xFFFFFFFF -shl (32 - $bits)) -band 0xFFFFFFFF)
      if (($baseInt -band $mask) -eq ($addrInt -band $mask)) { return $true }
    }
  }
  return $false
}

function Update-SshBans {
  param(
    [int]$Port,
    [string[]]$Ignore,
    [string[]]$ExtraExempt
  )
  $now = [DateTime]::UtcNow
  $bans = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'ContinuumMPC-ssh-ban-*' })
  foreach ($rule in $bans) {
    $desc = [string]$rule.Description
    if ($desc -match 'expires=([0-9TZ:\-]+)') {
      $expires = [DateTime]::Parse($Matches[1], $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
      if ($expires -le $now) {
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
      }
    }
  }

  $since = (Get-Date).AddMinutes(-10)
  try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -ErrorAction Stop)
  } catch {
    Write-Warning "Security log is not readable, so SSH bans were not updated. Allow rules are still applied. $_"
    return
  }
  $counts = @{}
  foreach ($ev in $events) {
    $xml = [xml]$ev.ToXml()
    $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -First 1
    if (-not $node) { continue }
    $ip = [string]$node.'#text'
    if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
    if (Test-PrivateOrIgnore -Ip $ip -Ignore @($Ignore + $ExtraExempt)) { continue }
    if (-not $counts.ContainsKey($ip)) { $counts[$ip] = 0 }
    $counts[$ip]++
  }
  $until = $now.AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
  foreach ($ip in $counts.Keys) {
    if ($counts[$ip] -lt 6) { continue }
    $name = 'ContinuumMPC-ssh-ban-' + ($ip -replace '\.', '-')
    $existing = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ($existing) { continue }
    New-NetFirewallRule -Name $name -DisplayName $name -Direction Inbound -Action Block `
      -Protocol TCP -LocalPort "$Port" -RemoteAddress $ip -Profile Any `
      -Description "expires=$until" | Out-Null
    Write-Host "Blocked SSH from $ip until $until"
  }
}

function Apply-Firewall {
  $plan = Read-PlanText -Text (Get-PlanFromWsl)
  Remove-NamedRules -Prefix 'ContinuumMPC-allow-'
  $ports = New-Object System.Collections.Generic.List[int]
  foreach ($port in $plan.Caps) { [void]$ports.Add([int]$port) }
  if ($plan.SshPort -gt 0 -and -not $ports.Contains([int]$plan.SshPort)) {
    [void]$ports.Add([int]$plan.SshPort)
  }
  foreach ($port in $ports) {
    if ($plan.ScanDrop -and $port -eq $plan.ScanPort) { continue }
    Add-AllowPort -Port $port
  }
  if ($plan.ScanDrop -and $plan.ScanPort -gt 0) {
    if ($plan.ScanSources.Count -gt 0) {
      Add-AllowPort -Port $plan.ScanPort -RemoteAddress $plan.ScanSources
      Write-Host "TCP $($plan.ScanPort) allow is limited to $($plan.ScanSources -join ', '). Docker Desktop's own application allow can still admit other addresses; no world Block was added."
    } else {
      Add-AllowPort -Port $plan.ScanPort
    }
  }
  Update-SshBans -Port $plan.SshPort -Ignore $plan.Ignore -ExtraExempt $plan.ScanSources
  Write-Host "Windows firewall rules refreshed."
}

function Install-FirewallTask {
  if (-not $Distro) { throw '-Distro is required to install the firewall task' }
  if (-not $Repo) { throw '-Repo is required to install the firewall task' }
  $dir = Get-ContinuumDir
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $dir 'mpc-auth-firewall.ps1') -Force
  Set-Content -LiteralPath (Join-Path $dir 'distro.txt') -Value $Distro -Encoding ascii
  Set-Content -LiteralPath (Join-Path $dir 'repo.txt') -Value $Repo -Encoding ascii
  $cmdPath = Join-Path $dir 'continuum-firewall.cmd'
  @(
    '@echo off'
    'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0mpc-auth-firewall.ps1" -Action apply'
  ) | Set-Content -LiteralPath $cmdPath -Encoding ascii
  foreach ($task in @($TaskLogon, $TaskPoll)) {
    & schtasks.exe /Query /TN $task 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
      & schtasks.exe /Delete /TN $task /F | Out-Null
    }
  }
  $tr = '"' + $cmdPath + '"'
  & schtasks.exe /Create /TN $TaskLogon /TR $tr /SC ONLOGON /RL HIGHEST /F
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Could not register $TaskLogon. From an elevated PowerShell run: & '$dir\mpc-auth-firewall.ps1' -Action apply"
  } else {
    & schtasks.exe /Create /TN $TaskPoll /TR $tr /SC MINUTE /MO 5 /RL HIGHEST /F
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Could not register the 5-minute firewall poll. The logon task is registered."
    } else {
      Write-Host "Registered $TaskLogon and $TaskPoll."
    }
  }
  try {
    Apply-Firewall
  } catch {
    Write-Warning "Windows Firewall rules were not applied. From an elevated PowerShell run: & '$dir\mpc-auth-firewall.ps1' -Action apply"
    Write-Warning $_
  }
}

function Remove-FirewallTask {
  foreach ($task in @($TaskLogon, $TaskPoll)) {
    & schtasks.exe /Query /TN $task 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
      & schtasks.exe /Delete /TN $task /F | Out-Null
      Write-Host "Deleted scheduled task $task"
    }
  }
  Remove-NamedRules -Prefix 'ContinuumMPC-allow-'
  Remove-NamedRules -Prefix 'ContinuumMPC-ssh-ban-'
  $dir = Get-ContinuumDir
  foreach ($name in @('mpc-auth-firewall.ps1', 'continuum-firewall.cmd', 'distro.txt', 'repo.txt')) {
    $path = Join-Path $dir $name
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
  }
}

switch ($Action) {
  'install' { Install-FirewallTask }
  'remove' { Remove-FirewallTask }
  'apply' { Apply-Firewall }
}
