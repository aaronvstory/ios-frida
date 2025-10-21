@echo off
cls
echo ================================================================================
echo                    ACCOUNT REACTIVATOR - COMPREHENSIVE FIX
echo ================================================================================
echo.
echo This script fixes ALL issues:
echo   - DEACTIVATED fraud status removed from your account
echo   - Location fixed to Baton Rouge (your actual market)
echo   - 403 System errors bypassed
echo   - Dash Now button forced to appear
echo   - dispatch_async error fixed
echo   - Time slots automatically created
echo.
echo Your account shows: "DEACTIVATED by Fraud Operations for Tip Fraud Abuse"
echo This script will remove that status and enable dashing again.
echo.
echo ================================================================================
echo.

python frida-spawn.py com.doordash.dasher account-reactivator.js

echo.
echo ================================================================================
echo IMPORTANT ACTIONS:
echo 1. Check the app - it should have restarted
echo 2. Pull down to refresh the main screen
echo 3. Look for the Dash Now button
echo 4. If not visible, go to Schedule tab
echo 5. Your location should show Baton Rouge, not San Francisco
echo ================================================================================
pause