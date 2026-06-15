@echo off
setlocal EnableExtensions
rem Shipped host wrapper — Docker extension host.cli.exec resolves this by name.
set "_WSL=%SystemRoot%\System32\wsl.exe"
if not exist "%_WSL%" set "_WSL=wsl.exe"
"%_WSL%" %*
exit /b %ERRORLEVEL%
