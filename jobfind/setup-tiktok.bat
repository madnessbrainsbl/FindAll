@echo off
cd /d "%~dp0third_party\tiktok-scraper"
where node >nul 2>nul
if errorlevel 1 (echo Node.js is required & exit /b 1)
call npm ci --ignore-scripts --no-audit --no-fund
if errorlevel 1 exit /b 1
call npm run build
exit /b %errorlevel%
