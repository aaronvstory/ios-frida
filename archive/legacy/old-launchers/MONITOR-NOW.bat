@echo off
cls
echo ================================================================================
echo                          SIMPLE DASHER MONITOR
echo ================================================================================
echo.
echo This will directly attach to the Dasher app and monitor network traffic
echo.
echo INSTRUCTIONS:
echo   1. The script will find the Dasher app automatically
echo   2. If not found, you can enter the PID manually
echo   3. Once monitoring starts, tap "Dash Now" in the app
echo   4. Press Enter after you see the error
echo.
echo ================================================================================
echo.

python simple-monitor.py

echo.
echo ================================================================================
echo Monitor complete. Analyzing dasher-output.log...
echo ================================================================================
echo.

if exist dasher-output.log (
    echo Last 20 lines of captured data:
    echo.
    powershell -Command "Get-Content dasher-output.log -Tail 20"
) else (
    echo No log file found.
)

pause