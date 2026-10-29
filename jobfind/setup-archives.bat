@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" python -m venv .venv
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check "tldextract==5.3.2" "termcolor>=2.4,<4" "PyYAML>=6,<7" "requests>=2.32" "psutil>=5.4.8"
exit /b %errorlevel%
