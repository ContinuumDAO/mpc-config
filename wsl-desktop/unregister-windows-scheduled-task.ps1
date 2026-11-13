#Requires -Version 5.1
<#
.SYNOPSIS
  Remove Windows Scheduled Tasks installed for the Continuum WSL pending-update watcher.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$failed = $false
foreach ($t in @(
  'ContinuumNodeMpcAuthWatcher',
  'ContinuumNodeMpcAuthWatcherPoll',
  'ContinuumNodeMpcAuthFirewall',
  'ContinuumNodeMpcAuthFirewallPoll'
)) {
  schtasks /Query /TN $t 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) {
    schtasks /Delete /TN $t /F
    if ($LASTEXITCODE -ne 0) {
      Write-Host "warning: failed to delete scheduled task $t"
      $failed = $true
    } else {
      Write-Host "Deleted scheduled task $t"
    }
  } else {
    Write-Host "Scheduled task $t not present."
  }
}

Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -like 'ContinuumMPC-allow-*' -or $_.Name -like 'ContinuumMPC-ssh-ban-*' } |
  ForEach-Object { Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue }

if ($failed) { exit 1 }
exit 0
