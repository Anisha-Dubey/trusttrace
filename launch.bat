@echo off
setlocal
title TRUSTTRACE - Evidence Passport for Web Threat Triage

echo ============================================================
echo   TRUSTTRACE - HackMatrix '26 Launch System
echo   Evidence Passport for Web Threat ^& Digital Trust Triage
echo ============================================================
echo.

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not found in your system PATH.
    echo Please install Python 3.10+ or add it to PATH.
    echo.
    pause
    exit /b 1
)

echo Initializing environment...
set PYTHONPATH=%~dp0src
cd /d "%~dp0"

echo Launching TRUSTTRACE at http://localhost:8000 ...
python run_app.py

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Application terminated with an error.
    pause
)
