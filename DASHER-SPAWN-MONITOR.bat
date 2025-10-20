@echo off
REM ============================================================================
REM DASHER SPAWN MONITOR - Launch Dasher with Frida
REM ============================================================================
REM Spawns the Dasher app fresh with Frida monitoring
REM ============================================================================

echo.
echo ============================================================
echo    DASHER SPAWN MONITOR - Fresh Launch
echo ============================================================
echo.
echo Device: Pixel 4 (Android) via USB
echo App: DoorDash Dasher (com.doordash.driverapp)
echo.
echo This will:
echo   1. Kill any running Dasher app
echo   2. Launch Dasher fresh with Frida attached
echo   3. Load complete monitoring + SSL bypass + proxy script
echo.
echo Make sure:
echo   - HTTP Toolkit is running on 192.168.50.9:8000
echo.
pause

python live-frida-repl.py com.doordash.driverapp --spawn

pause
