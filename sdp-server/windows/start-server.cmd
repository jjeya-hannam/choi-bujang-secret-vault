@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0.."
where node >nul 2>nul
if errorlevel 1 goto failed
set "ON_ENGINE_ADAPTER="
set "ON_AI_BASE_URL="
set "ON_AI_APP_KEY="
set "OPENAI_API_KEY="
node tools\windows-preflight.mjs server
exit /b %errorlevel%
:failed
echo SDP_WINDOWS_START_FAILED
exit /b 1
