@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\pythonw.exe" (
  start "" ".venv\Scripts\pythonw.exe" jobfind.py --db "..\jobfind.db" network-ui
  exit /b 0
)
python jobfind.py --db "..\jobfind.db" network-ui
exit /b %errorlevel%
