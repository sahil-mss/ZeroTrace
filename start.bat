@echo off
title ZeroTrace Launcher
echo ==============================================================
echo            Starting ZeroTrace (Backend + Frontend)
echo ==============================================================
echo.

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" launch.py
) else (
    python launch.py
)

pause
