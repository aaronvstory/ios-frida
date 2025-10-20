@echo off
chcp 437 >nul 2>&1
cls

echo ================================================================================
echo                        LIVE DASHER MONITOR
echo ================================================================================
echo.
echo This will monitor the DoorDash Dasher app in real-time
echo I (Claude) will watch the output when you tap "Dash Now"
echo.
echo INSTRUCTIONS:
echo   1. Make sure the Dasher app is already running
echo   2. Navigate to where you can tap "Dash Now"
echo   3. When the monitor says "READY", tap "Dash Now"
echo   4. After you see the error, type "done" and press Enter
echo   5. I'll analyze the captured data
echo.
echo ================================================================================
echo.
pause

python live-monitor.py

echo.
echo ================================================================================
echo Monitor session complete. Check dasher-monitor-log.json for details
echo ================================================================================
pause