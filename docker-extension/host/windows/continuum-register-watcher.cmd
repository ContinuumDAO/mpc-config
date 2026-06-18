@echo off
setlocal EnableExtensions
rem Register Windows logon Scheduled Task to start the WSL pending-update watcher.
rem Shipped with the Continuum Docker extension (host.binaries).
rem Usage: continuum-register-watcher.cmd <WslDistroName>

set "DISTRO=%~1"
if "%DISTRO%"=="" (
  echo error: WSL distro name required >&2
  echo usage: %~nx0 Ubuntu-24.04 >&2
  exit /b 1
)

set "WSL=%SystemRoot%\System32\wsl.exe"
if not exist "%WSL%" set "WSL=wsl.exe"

set "TASK=ContinuumNodeMpcAuthWatcher"
set "TR=wsl.exe -d %DISTRO% -- bash -lc \"~/mpc-config/wsl-desktop/start-watcher.sh\""

schtasks /Query /TN "%TASK%" >nul 2>&1
if %ERRORLEVEL%==0 (
  schtasks /Delete /TN "%TASK%" /F >nul 2>&1
)

schtasks /Create /TN "%TASK%" /TR "%TR%" /SC ONLOGON /RL LIMITED /F
if %ERRORLEVEL% neq 0 (
  echo warning: schtasks create failed — start watcher manually in WSL: ~/mpc-config/wsl-desktop/start-watcher.sh >&2
  exit /b 1
)

echo Registered logon task "%TASK%" for distro %DISTRO%.
exit /b 0
