@echo off
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
if not exist ".tools-venv\Scripts\ghunt.exe" call setup-research-tools.bat
if errorlevel 1 exit /b 1
".tools-venv\Scripts\ghunt.exe" login
exit /b %errorlevel%
