@echo off
cls
echo ================================================================================
echo                     ULTIMATE 403 BYPASS - 4 METHODS
echo ================================================================================
echo.
echo This uses 4 different methods to bypass the 403 error:
echo   1. Network response modification - Changes 403 to 200
echo   2. NSError prevention - Blocks error creation
echo   3. Status code override - Forces success status
echo   4. Alert suppression - Hides error dialogs
echo.
echo ================================================================================
echo.
echo Starting with SPAWN mode for clean injection...
echo.

python frida-spawn.py com.doordash.dasher ultimate-403-bypass.js

echo.
echo ================================================================================
echo Bypass active. The error should be gone now.
echo ================================================================================
pause