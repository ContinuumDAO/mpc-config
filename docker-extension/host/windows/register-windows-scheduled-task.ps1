#Requires -Version 5.1
<#
.SYNOPSIS
  Register Windows Scheduled Tasks that start the Continuum WSL pending-update watcher.

.PARAMETER Distro
  WSL distro name as shown by wsl -l -v (e.g. Ubuntu-24.04).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string] $Distro
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$tr = "wsl.exe -d $Distro -- bash -lc `"~/mpc-config/wsl-desktop/start-watcher.sh`""
foreach ($t in @('ContinuumNodeMpcAuthWatcher', 'ContinuumNodeMpcAuthWatcherPoll')) {
  schtasks /Query /TN $t 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) {
    schtasks /Delete /TN $t /F 2>$null | Out-Null
  }
}

schtasks /Create /TN 'ContinuumNodeMpcAuthWatcher' /TR $tr /SC ONLOGON /RL LIMITED /F
if ($LASTEXITCODE -ne 0) {
  Write-Host 'warning: schtasks ONLOGON failed'
  exit 1
}
schtasks /Create /TN 'ContinuumNodeMpcAuthWatcherPoll' /TR $tr /SC MINUTE /MO 5 /RL LIMITED /F
if ($LASTEXITCODE -ne 0) {
  Write-Host 'warning: schtasks MINUTE poll failed'
  exit 1
}
Write-Host "Registered logon + 5-minute tasks for distro $Distro."
exit 0
