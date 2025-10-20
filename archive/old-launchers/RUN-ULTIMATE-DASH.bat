@echo off
cls
echo ================================================================================
echo                    ULTIMATE DASH ENABLER - FINAL SOLUTION
echo ================================================================================
echo.
echo This script:
echo   - Forces Dash Now button to appear
echo   - Overrides ALL server restrictions
echo   - Spoofs location to busy market (San Francisco)
echo   - Enables all disabled UI elements
echo   - Modifies API responses in real-time
echo.
echo STEPS:
echo   1. Run this script
echo   2. App will restart with modifications
echo   3. Pull down to refresh main screen
echo   4. Dash Now button should appear
echo   5. If not, navigate to Schedule tab
echo.
echo ================================================================================
echo.

python frida-spawn.py com.doordash.dasher ultimate-dash-enabler.js

echo.
echo ================================================================================
echo CHECK THE APP NOW!
echo - Pull down to refresh
echo - Look for Dash Now button
echo - Check Schedule tab if needed
echo ================================================================================
pause