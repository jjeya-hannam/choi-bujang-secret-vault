@echo off
setlocal
cd /d "%~dp0.."
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 24.19.0 is required. Install it from the official Node.js website.
  pause
  exit /b 1
)
echo Student local PC dashboard. Security lesson data is demo; PC measurements are real and manual.
echo Open http://127.0.0.1:5189 and stop with Ctrl+C.
node student/pc-server.mjs --demo
pause
