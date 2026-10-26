@echo off
setlocal
cd /d "%~dp0.."
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 24.19.0 is required. Install it from the official Node.js website.
  pause
  exit /b 1
)
node tools\check-environment.mjs
if errorlevel 1 (
  pause
  exit /b 1
)
set "ON_PORT=5189"
echo Student local PC dashboard. Security lesson data is demo; PC measurements are real and manual.
echo Open http://127.0.0.1:5189 and stop with Ctrl+C.
node student/pc-server.mjs --demo
set "APP_EXIT=%errorlevel%"
pause
exit /b %APP_EXIT%
