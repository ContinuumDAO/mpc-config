@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Shipped host wrapper — Docker extension host.cli.exec resolves this by name.
rem Delegates to wsl.exe for normal calls. Before the desktop orchestrator runs
rem (bash … continuum-desktop-orchestrate.sh → git clone mpc-config), runs
rem preflight-windows.ps1 on the Windows host (AV + WSL/GitHub checks).

set "_WSL=%SystemRoot%\System32\wsl.exe"
if not exist "%_WSL%" set "_WSL=wsl.exe"
set "_HOSTDIR=%~dp0"
set "_PREFLIGHT=%_HOSTDIR%preflight-windows.ps1"
set "_REGISTER_CMD=%_HOSTDIR%continuum-register-watcher.cmd"
set "_REGISTER_PS1=%_HOSTDIR%register-windows-scheduled-task.ps1"

rem Explicit preflight (optional): continuum-wsl.cmd preflight -WslDistro Ubuntu-24.04
if /I "%~1"=="preflight" (
  shift
  call :RunPreflight %*
  exit /b !ERRORLEVEL!
)

rem Start WSL pending-update watcher: continuum-wsl.cmd start-watcher -WslDistro Ubuntu-24.04
if /I "%~1"=="start-watcher" (
  shift
  call :StartWatcher %*
  exit /b !ERRORLEVEL!
)

rem Register logon + 5-minute Scheduled Tasks: continuum-wsl.cmd register-watcher -WslDistro Ubuntu-24.04
if /I "%~1"=="register-watcher" (
  shift
  call :RegisterWatcher %*
  exit /b !ERRORLEVEL!
)

set "_RUN_PREFLIGHT=0"
echo %* | findstr /I /C:"continuum-desktop-orchestrate.sh" >nul 2>&1
if !ERRORLEVEL! equ 0 set "_RUN_PREFLIGHT=1"

if "!_RUN_PREFLIGHT!"=="1" (
  if not defined CONTINUUM_SKIP_PREFLIGHT (
    call :ExtractDistro %*
    if defined _DISTRO (
      call :RunPreflight -WslDistro "!_DISTRO!"
      if !ERRORLEVEL! neq 0 exit /b !ERRORLEVEL!
    ) else (
      echo warning: could not determine WSL distro for preflight; continuing without host checks. >&2
    )
  )
)

"%_WSL%" %*
exit /b %ERRORLEVEL%

:ExtractDistro
set "_DISTRO="
set "_WANT="
for %%A in (%*) do (
  if defined _WANT (
    set "_DISTRO=%%~A"
    set "_WANT="
    goto :eof
  )
  if /I "%%~A"=="-d" set "_WANT=1"
)
goto :eof

:ParseWslDistroArg
set "_DISTRO="
set "_WANT="
for %%A in (%*) do (
  if defined _WANT (
    set "_DISTRO=%%~A"
    set "_WANT="
    goto :eof
  )
  if /I "%%~A"=="-WslDistro" set "_WANT=1"
)
goto :eof

:StartWatcher
call :ParseWslDistroArg %*
if defined _DISTRO (
  "%_WSL%" -d !_DISTRO! -- bash -lc "~/mpc-config/wsl-desktop/start-watcher.sh"
) else (
  "%_WSL%" -- bash -lc "~/mpc-config/wsl-desktop/start-watcher.sh"
)
exit /b %ERRORLEVEL%

:RegisterWatcher
call :ParseWslDistroArg %*
if not defined _DISTRO (
  echo error: -WslDistro is required for register-watcher >&2
  exit /b 1
)
if exist "%_REGISTER_CMD%" (
  call "%_REGISTER_CMD%" "!_DISTRO!"
  exit /b !ERRORLEVEL!
)
if exist "%_REGISTER_PS1%" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%_REGISTER_PS1%" -Distro "!_DISTRO!"
  exit /b !ERRORLEVEL!
)
echo error: missing continuum-register-watcher.cmd and register-windows-scheduled-task.ps1 beside %~nx0 >&2
exit /b 1

:RunPreflight
if not exist "%_PREFLIGHT%" (
  echo warning: missing %_PREFLIGHT% — skipping Windows preflight. >&2
  exit /b 0
)

set "_PF_ARGS=-NonInteractive"
if defined CONTINUUM_PREFLIGHT_CONTINUE_ON_AV set "_PF_ARGS=!_PF_ARGS! -ContinueOnAvWarning"

powershell -NoProfile -ExecutionPolicy Bypass -File "%_PREFLIGHT%" !_PF_ARGS! %*
set "_RC=!ERRORLEVEL!"

if "!_RC!"=="0" exit /b 0

if "!_RC!"=="10" (
  echo. >&2
  echo Install paused: real-time antivirus protection is active. >&2
  echo Turn off Real-time protection for about 30 minutes, then click Install again. >&2
  echo Windows Security -^> Virus ^& threat protection -^> Manage settings. >&2
  exit /b 10
)

if "!_RC!"=="11" (
  echo. >&2
  echo Install failed: GitHub is not reachable from WSL ^(git probe failed^). >&2
  echo See preflight output above, then retry Install. >&2
  exit /b 11
)

if "!_RC!"=="12" (
  echo. >&2
  echo Install failed: docker compose is not available in WSL. >&2
  echo Enable Docker Desktop WSL integration for your distro, then retry. >&2
  exit /b 12
)

if "!_RC!"=="13" (
  echo. >&2
  echo Install failed: WSL distro not found or misconfigured. >&2
  exit /b 13
)

exit /b !_RC!
