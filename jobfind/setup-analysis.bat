@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" exit /b 1
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements-analysis.txt
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" jobfind.py statistics --install-model
exit /b %errorlevel%
