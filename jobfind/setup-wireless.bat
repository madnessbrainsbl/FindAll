@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install -r requirements-wireless.txt
if errorlevel 1 exit /b 1
echo Wireless telemetry and BLE dependencies installed.
