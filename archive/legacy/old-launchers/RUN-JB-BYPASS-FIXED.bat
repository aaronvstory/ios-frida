@echo off
cls
echo ================================================================================
echo                 JAILBREAK BYPASS - FIXED VERSION
echo ================================================================================
echo.
echo This fixes the UIApplication error and adds more bypasses.
echo.
echo CRITICAL STEPS FOR SUCCESS:
echo   1. Run this script
echo   2. When app loads, GO TO SETTINGS/ACCOUNT
echo   3. TAP "LOG OUT"
echo   4. LOG BACK IN with your credentials
echo   5. Try "Dash Now" with fresh session
echo.
echo The fresh login creates a new session without jailbreak flags!
echo.
echo ================================================================================
echo.

python frida-spawn.py com.doordash.dasher jailbreak-bypass-fixed.js

echo.
echo ================================================================================
echo DID YOU LOG OUT AND LOG BACK IN?
echo This is CRITICAL for removing the server-side block!
echo ================================================================================
pause