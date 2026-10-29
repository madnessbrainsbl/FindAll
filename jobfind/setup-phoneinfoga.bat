@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-phoneinfoga.ps1"
exit /b %errorlevel%
