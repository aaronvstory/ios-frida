@echo off
chcp 437 >nul 2>&1
cls

echo ================================================================================
echo                    ENHANCED DASHER MONITOR - CLAUDE WATCHING
echo ================================================================================
echo.
echo I (Claude) am ready to monitor your Dasher app in real-time!
echo.
echo STEPS:
echo   1. Make sure Dasher app is running
echo   2. Navigate to the Dash Now screen
echo   3. When you see "MONITORING ACTIVE" below, follow these commands:
echo.
echo      Type 'tapped' right after you tap "Dash Now"
echo      Type 'error' when you see the error message
echo      Type 'done' to save and analyze
echo.
echo This will capture ALL network traffic, errors, and analytics events
echo.
echo ================================================================================
echo.
pause

python enhanced-live-monitor.py

echo.
echo ================================================================================
echo Check the timestamped JSON file for complete capture data
echo ================================================================================
pause