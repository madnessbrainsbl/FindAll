@echo off
cd /d "%~dp0"
".venv\Scripts\python.exe" -m pip install -r requirements-library.txt
if errorlevel 1 exit /b %errorlevel%
".venv\Scripts\python.exe" jobfind.py library --action setup
exit /b %errorlevel%
