@echo off
cls
echo ================================================================================
echo                     SPAWN MONITOR - DASHER APP
echo ================================================================================
echo.
echo This will RESTART the Dasher app with monitoring enabled from the start.
echo.
echo IMPORTANT: The app will close and reopen - you'll need to log in again.
echo.
echo Steps:
echo   1. App will restart automatically
echo   2. Log in to your Dasher account
echo   3. Navigate to where you can tap "Dash Now"
echo   4. Tap "Dash Now" and wait for the error
echo   5. Press ENTER to see captured errors
echo.
echo ================================================================================
echo.
pause

python spawn-monitor.py

echo.
echo ================================================================================
echo CHECKING CAPTURED DATA...
echo ================================================================================
echo.

if exist dasher-spawn-log.txt (
    echo Last 30 lines of log:
    echo.
    powershell -Command "Get-Content dasher-spawn-log.txt -Tail 30"
    echo.
    echo Full log saved in: dasher-spawn-log.txt
) else (
    echo No log file created.
)

echo.
pause