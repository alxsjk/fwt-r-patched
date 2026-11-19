@echo off
setlocal
title FWT Reborn - Client Patcher

echo ========================================================
echo   FWT Reborn - Offline Client Patcher Launcher
echo ========================================================
echo.

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python was not found on your PATH.
    echo Please install Python 3.12 or newer from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [*] Installing required dependencies...
    .venv\Scripts\python.exe -m pip install --upgrade pip
    .venv\Scripts\python.exe -m pip install -e ".[assets]" || .venv\Scripts\python.exe -m pip install -r requirements.txt
)

echo [*] Starting FWT Reborn GUI...
start "" .venv\Scripts\python.exe fwt_patcher.py --gui
