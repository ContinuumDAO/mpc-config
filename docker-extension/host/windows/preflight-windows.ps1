#Requires -Version 5.1
<#
.SYNOPSIS
  Windows preflight for Continuum node install (Docker Desktop extension / WSL path).

.DESCRIPTION
  Runs on the Windows host before mpc-config is cloned inside WSL. Checks:
    1. WSL distro exists and docker compose is available (Docker Desktop integration).
    2. GitHub reachability from WSL (git ls-remote + optional shallow clone probe).
    3. Active real-time antivirus (Microsoft Defender + registered third-party products).

  Shipped beside continuum-wsl.cmd in the continuum-node-installer extension image:
  host/windows/preflight-windows.ps1 (invoked automatically before git clone).

.PARAMETER WslDistro
  WSL distro name as shown by `wsl -l -v` (e.g. Ubuntu-24.04). Auto-detected when omitted.

.PARAMETER ContinueOnAvWarning
  Exit 0 even when real-time AV protection is active (user acknowledged the warning).

.PARAMETER SkipNetworkProbe
  Skip GitHub git probes in WSL (AV check and Docker/WSL checks still run).

.PARAMETER SkipCloneProbe
  Run ls-remote only; skip shallow clone probe (faster, less thorough).

.PARAMETER NonInteractive
  Do not prompt; rely on exit codes and printed guidance.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File preflight-windows.ps1 -WslDistro Ubuntu-24.04

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File preflight-windows.ps1 -ContinueOnAvWarning

.NOTES
  Exit codes:
    0  — preflight passed (or AV warning acknowledged via -ContinueOnAvWarning)
    10 — real-time antivirus protection active; user should adjust settings and retry
    11 — GitHub / git network probe failed in WSL
    12 — WSL distro missing or docker compose unavailable in WSL
    13 — preflight misconfiguration (e.g. no WSL distro found)
#>

[CmdletBinding()]
param(
  [string] $WslDistro = '',
  [switch] $ContinueOnAvWarning,
  [switch] $SkipNetworkProbe,
  [switch] $SkipCloneProbe,
  [switch] $NonInteractive,
  [string] $MpcConfigRepo = 'https://github.com/ContinuumDAO/mpc-config.git',
  [string] $CloneProbeDir = '/tmp/continuum-mpc-config-preflight-probe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ExitOk = 0
$script:ExitAvActive = 10
$script:ExitNetworkFailed = 11
$script:ExitDockerWslFailed = 12
$script:ExitConfigFailed = 13

function Write-Step {
  param([string] $Message)
  Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Pass {
  param([string] $Message)
  Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnLine {
  param([string] $Message)
  Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-FailLine {
  param([string] $Message)
  Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Blank {
  Write-Host ''
}

function Get-RealTimeProtectionFromProductState {
  param([uint32] $ProductState)

  # SecurityCenter2 productState: middle hex byte '10' => real-time protection on.
  $hex = ('{0:X6}' -f $ProductState)
  if ($hex.Length -lt 6) {
    $hex = $hex.PadLeft(6, '0')
  }
  $rtByte = $hex.Substring(2, 2)
  return ($rtByte -eq '10')
}

function Get-RegisteredAntivirusProducts {
  $products = @()

  try {
    $cim = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
    foreach ($item in @($cim)) {
      $displayName = [string]$item.displayName
      if ([string]::IsNullOrWhiteSpace($displayName)) {
        $displayName = 'Unknown antivirus product'
      }
      $products += [pscustomobject]@{
        Name                        = $displayName.Trim()
        RealTimeProtectionEnabled   = Get-RealTimeProtectionFromProductState -ProductState ([uint32]$item.productState)
        ProductStateHex             = ('0x{0:X}' -f [uint32]$item.productState)
        Source                      = 'SecurityCenter2'
      }
    }
  }
  catch {
    Write-WarnLine "Could not query root\SecurityCenter2 AntiVirusProduct: $($_.Exception.Message)"
  }

  return $products
}

function Get-DefenderStatus {
  try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    return [pscustomobject]@{
      Available                   = $true
      RealTimeProtectionEnabled   = [bool]$status.RealTimeProtectionEnabled
      IoavProtectionEnabled       = [bool]$status.IoavProtectionEnabled
      TamperProtectionEnabled     = [bool]$status.IsTamperProtected
      AntivirusEnabled            = [bool]$status.AntivirusEnabled
    }
  }
  catch {
    return [pscustomobject]@{
      Available                   = $false
      RealTimeProtectionEnabled   = $false
      IoavProtectionEnabled       = $false
      TamperProtectionEnabled     = $false
      AntivirusEnabled            = $false
      Error                       = $_.Exception.Message
    }
  }
}

function Get-ActiveAntivirusSummary {
  $active = @()
  $seen = @{}

  $defender = Get-DefenderStatus
  if ($defender.Available -and $defender.RealTimeProtectionEnabled) {
    $name = 'Microsoft Defender Antivirus'
    if (-not $seen.ContainsKey($name)) {
      $seen[$name] = $true
      $active += [pscustomobject]@{
        Name                      = $name
        RealTimeProtectionEnabled = $true
        TamperProtectionEnabled   = $defender.TamperProtectionEnabled
        Notes                     = if ($defender.IoavProtectionEnabled) { 'Download/network inspection may be enabled (IOAV).' } else { '' }
      }
    }
  }

  foreach ($product in Get-RegisteredAntivirusProducts) {
    if (-not $product.RealTimeProtectionEnabled) { continue }
    $name = $product.Name
    if ($seen.ContainsKey($name)) { continue }
    $seen[$name] = $true
    $active += [pscustomobject]@{
      Name                      = $name
      RealTimeProtectionEnabled = $true
      TamperProtectionEnabled   = $null
      Notes                     = "productState $($product.ProductStateHex)"
    }
  }

  return [pscustomobject]@{
    ActiveProducts = @($active)
    Defender       = $defender
  }
}

function Write-AntivirusRecommendation {
  param(
    [object[]] $ActiveProducts
  )

  Write-Blank
  Write-Host 'Security software may interrupt large Git downloads inside WSL.' -ForegroundColor Yellow
  Write-Host 'Recommended before retrying install:' -ForegroundColor Yellow
  Write-Host '  1. Open Windows Security -> Virus & threat protection -> Manage settings.'
  Write-Host '  2. Turn off Real-time protection for about 30 minutes while the install runs.'
  Write-Host '     Re-enable it when the Continuum Docker extension reports Install complete.'
  Write-Host '  3. If Tamper protection blocks that toggle, turn Tamper protection off first,'
  Write-Host '     then disable Real-time protection for 30 minutes.'
  Write-Host ''
  Write-Host 'Alternative (keep protection on): add exclusions for Docker Desktop, WSL, and git.exe,'
  Write-Host 'or disable HTTPS/network scanning in your third-party antivirus settings.'
  Write-Blank

  if ($ActiveProducts.Count -gt 0) {
    Write-Host 'Detected active real-time protection:' -ForegroundColor Yellow
    foreach ($p in $ActiveProducts) {
      $extra = if ([string]::IsNullOrWhiteSpace($p.Notes)) { '' } else { " ($($p.Notes))" }
      Write-Host "  - $($p.Name)$extra"
    }
    Write-Blank
  }
}

function Get-WslDistroListingLines {
  # wsl -l -v output is occasionally UTF-16-ish when captured from PowerShell; strip NULs.
  foreach ($args in @(
      @('--list', '--verbose'),
      @('-l', '-v')
    )) {
    try {
      $raw = & wsl.exe @args 2>&1
      if ($LASTEXITCODE -ne 0) { continue }
      return @($raw | ForEach-Object { ("$_" -replace "`0", '').TrimEnd() } | Where-Object { $_ -ne '' })
    }
    catch {
      continue
    }
  }

  try {
    $quiet = & wsl.exe -l -q 2>&1
    if ($LASTEXITCODE -eq 0) {
      return @($quiet | ForEach-Object { ("$_" -replace "`0", '').Trim() } | Where-Object { $_ -ne '' })
    }
  }
  catch {
    return @()
  }

  return @()
}

function Get-DefaultWslDistro {
  $lines = Get-WslDistroListingLines
  if ($lines.Count -eq 0) { return $null }

  foreach ($line in $lines) {
    if ($line -match '^\s*\*\s+(.+?)\s{2,}') {
      return $Matches[1].Trim()
    }
  }

  foreach ($line in $lines) {
    if ($line -match '^\s{0,1}([^*\s].+?)\s{2,}(Running|Stopped|Installing|Uninstalling)') {
      $name = $Matches[1].Trim()
      if ($name -notmatch '^(NAME|Windows Subsystem|docker-desktop|docker-desktop-data)$') {
        return $name
      }
    }
  }

  # wsl -l -q: one distro name per line, no docker-desktop entries.
  foreach ($line in $lines) {
    if ($line -notmatch '^(docker-desktop|docker-desktop-data)$') {
      return $line.Trim()
    }
  }

  return $null
}

function Test-WslDistroExists {
  param([string] $Distro)

  try {
    $null = & wsl.exe -d $Distro -e true 2>&1
    return ($LASTEXITCODE -eq 0)
  }
  catch {
    return $false
  }
}

function Invoke-WslBash {
  param(
    [string] $Distro,
    [string] $Command
  )

  # Single-quoted bash -lc argument for PowerShell.
  $escaped = $Command.Replace("'", "'\''")
  $output = & wsl.exe -d $Distro -e bash -lc $escaped 2>&1
  return [pscustomobject]@{
    ExitCode = $LASTEXITCODE
    Output   = (@($output) -join [Environment]::NewLine)
  }
}

function Test-DockerComposeInWsl {
  param([string] $Distro)

  $result = Invoke-WslBash -Distro $Distro -Command 'command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1'
  return ($result.ExitCode -eq 0)
}

function Test-GitHubLsRemoteInWsl {
  param(
    [string] $Distro,
    [string] $RepoUrl
  )

  $cmd = "command -v git >/dev/null 2>&1 || { echo 'git not installed in WSL'; exit 127; }; git -c http.version=HTTP/1.1 ls-remote '$RepoUrl' HEAD"
  $result = Invoke-WslBash -Distro $Distro -Command $cmd
  return $result
}

function Test-GitHubShallowCloneProbeInWsl {
  param(
    [string] $Distro,
    [string] $RepoUrl,
    [string] $ProbeDir
  )

  $cmd = @"
set -euo pipefail
command -v git >/dev/null 2>&1 || { echo 'git not installed in WSL'; exit 127; }
rm -rf '$ProbeDir'
git -c http.version=HTTP/1.1 clone --depth 1 --single-branch '$RepoUrl' '$ProbeDir'
test -d '$ProbeDir/.git'
rm -rf '$ProbeDir'
"@

  $result = Invoke-WslBash -Distro $Distro -Command $cmd
  return $result
}

function Write-NetworkFailureGuidance {
  param([string] $Detail)

  Write-Blank
  Write-FailLine 'GitHub access from WSL failed before mpc-config could be cloned.'
  if (-not [string]::IsNullOrWhiteSpace($Detail)) {
    Write-Host $Detail
  }
  Write-Blank
  Write-Host 'Try these steps in WSL, then rerun preflight:' -ForegroundColor Yellow
  Write-Host "  git -c http.version=HTTP/1.1 ls-remote $MpcConfigRepo HEAD"
  Write-Host '  sudo ip link set dev eth0 mtu 1350   # optional WSL2 MTU workaround'
  Write-Host '  Retry on a wired connection or mobile hotspot to rule out ISP/router issues.'
  Write-Blank
}

function Confirm-ContinueOnAvWarning {
  if ($ContinueOnAvWarning) { return $true }
  if ($NonInteractive) { return $false }

  Write-Blank
  $answer = Read-Host 'Real-time antivirus is active. Continue anyway? [y/N]'
  return ($answer -match '^(y|yes)$')
}

# --- Main ---

Write-Step 'Continuum node install — Windows preflight'
Write-Host "mpc-config repo: $MpcConfigRepo"
Write-Blank

if ([string]::IsNullOrWhiteSpace($WslDistro)) {
  $WslDistro = Get-DefaultWslDistro
}

if ([string]::IsNullOrWhiteSpace($WslDistro)) {
  Write-FailLine 'No WSL distro specified and none could be auto-detected.'
  Write-Host 'Install Ubuntu in WSL, or pass -WslDistro Ubuntu-24.04 (see wsl -l -v).'
  exit $script:ExitConfigFailed
}

Write-Host "WSL distro: $WslDistro"

if (-not (Test-WslDistroExists -Distro $WslDistro)) {
  Write-FailLine "WSL distro not found or not runnable: $WslDistro"
  Write-Host 'Run wsl -l -v and pass the exact distro name with -WslDistro.'
  exit $script:ExitConfigFailed
}
Write-Pass "WSL distro '$WslDistro' is available."

Write-Step 'Checking Docker Desktop WSL integration'
if (-not (Test-DockerComposeInWsl -Distro $WslDistro)) {
  Write-FailLine "docker compose is not available inside WSL distro '$WslDistro'."
  Write-Host 'In Docker Desktop: Settings -> General -> Use the WSL 2 based engine.'
  Write-Host 'Settings -> Resources -> WSL integration -> enable this distro, then restart Docker Desktop.'
  Write-Host "Verify: wsl -d $WslDistro docker compose version"
  exit $script:ExitDockerWslFailed
}
Write-Pass 'docker compose is available in WSL.'

$networkFailed = $false
$networkDetail = ''

if (-not $SkipNetworkProbe) {
  Write-Step 'Probing GitHub access from WSL (git ls-remote)'
  $lsRemote = Test-GitHubLsRemoteInWsl -Distro $WslDistro -RepoUrl $MpcConfigRepo
  if ($lsRemote.ExitCode -ne 0) {
    $networkFailed = $true
    $networkDetail = $lsRemote.Output
    Write-FailLine 'git ls-remote failed.'
    if ($networkDetail) { Write-Host $networkDetail }
  }
  else {
    Write-Pass 'git ls-remote succeeded (HTTP/1.1).'
  }

  if (-not $networkFailed -and -not $SkipCloneProbe) {
    Write-Step 'Probing shallow git clone (mpc-config download test)'
    $cloneProbe = Test-GitHubShallowCloneProbeInWsl -Distro $WslDistro -RepoUrl $MpcConfigRepo -ProbeDir $CloneProbeDir
    if ($cloneProbe.ExitCode -ne 0) {
      $networkFailed = $true
      $networkDetail = $cloneProbe.Output
      Write-FailLine 'Shallow clone probe failed.'
      if ($networkDetail) { Write-Host $networkDetail }
    }
    else {
      Write-Pass 'Shallow clone probe succeeded.'
    }
  }
}
else {
  Write-WarnLine 'Network probe skipped (-SkipNetworkProbe).'
}

if ($networkFailed) {
  Write-NetworkFailureGuidance -Detail $networkDetail
  exit $script:ExitNetworkFailed
}

Write-Step 'Checking antivirus / real-time protection'
$avSummary = Get-ActiveAntivirusSummary
$activeAv = @($avSummary.ActiveProducts)

if ($activeAv.Count -eq 0) {
  Write-Pass 'No active real-time antivirus protection detected (or status unavailable).'
  Write-Blank
  Write-Pass 'Preflight passed. Safe to continue with Continuum node install.'
  exit $script:ExitOk
}

Write-WarnLine ("Active real-time protection detected ({0} product(s))." -f $activeAv.Count)
Write-AntivirusRecommendation -ActiveProducts $activeAv

if (Confirm-ContinueOnAvWarning) {
  Write-WarnLine 'Continuing despite active real-time antivirus (-ContinueOnAvWarning or user confirmed).'
  exit $script:ExitOk
}

Write-FailLine 'Install blocked until real-time protection is adjusted or -ContinueOnAvWarning is passed.'
exit $script:ExitAvActive
