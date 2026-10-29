@echo off
setlocal
cd /d "%~dp0third_party\web-check"
where node >nul 2>nul
if errorlevel 1 (
  echo Web-Check requires Node.js 22.12 or newer.
  exit /b 1
)
if not exist "node_modules\express\package.json" (
  if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" set "PUPPETEER_SKIP_DOWNLOAD=1"
  call npm install --legacy-peer-deps --no-audit --no-fund
  if errorlevel 1 exit /b 1
)
call npm run build
exit /b %errorlevel%
