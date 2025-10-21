@echo off
cls
echo ================================================================================
echo                    QUICK DASHER FIX - ONE CLICK SOLUTION
echo ================================================================================
echo.
echo Target: DoorDash DASHER (com.doordash.dasher)
echo Fix: Analytics comprehensive spoofing
echo.
echo This will fix the "ErrorNetworking.ResponseStatusCodeError error 1"
echo.
pause

echo.
echo Starting DASHER app with analytics fix...
echo.

python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\analytics-comprehensive-spoof.js

echo.
echo ================================================================================
echo Please try "Dash Now" in the DASHER app
echo.
echo If you still get the error, press Ctrl+C and try:
echo   PowerShell -File FridaDasherLauncher.ps1
echo   Then select option [8] or [9]
echo ================================================================================
echo.
pause