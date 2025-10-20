@echo off
REM ============================================================================
REM DASHER LIVE MONITOR - Interactive Frida REPL
REM ============================================================================
REM Launches the interactive Frida REPL for DoorDash Dasher app
REM ============================================================================

echo.
echo ============================================================
echo    DASHER LIVE MONITOR - Interactive Frida REPL
echo ============================================================
echo.
echo Device: Pixel 4 (Android) via USB
echo App: DoorDash Dasher (com.doordash.driverapp)
echo.
echo This will attach to the running Dasher app and load the
echo complete monitoring + SSL bypass + proxy script.
echo.
echo Make sure:
echo   1. Dasher app is already running on your phone
echo   2. HTTP Toolkit is running on 192.168.50.9:8000
echo.
pause

python live-frida-repl.py com.doordash.driverapp

pause
