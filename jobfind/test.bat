@echo off
setlocal
cd /d "%~dp0"
set "TEST_PYTHON=python"
if exist ".venv\Scripts\python.exe" set "TEST_PYTHON=%~dp0.venv\Scripts\python.exe"
"%TEST_PYTHON%" -m unittest discover -s tests -v
if errorlevel 1 exit /b 1
"%TEST_PYTHON%" tests\test_github_email.py
if errorlevel 1 exit /b 1
"%TEST_PYTHON%" -m tests.test_unified_osint
if errorlevel 1 exit /b 1
for %%M in (jf.ai_agents jf.ai_cli jf.osint jf.osint_contacts jf.domain_recon jf.github_tools) do (
  "%TEST_PYTHON%" -m %%M
  if errorlevel 1 exit /b 1
)
set "TEST_CARGO=%USERPROFILE%\.cargo\bin\cargo.exe"
if not exist "%TEST_CARGO%" set "TEST_CARGO=cargo"
"%TEST_CARGO%" test --locked --manifest-path rust-ui\Cargo.toml
exit /b %errorlevel%
