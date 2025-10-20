@echo off
cls
echo ================================================================================
echo                        DASHER NETWORK CAPTURE
echo ================================================================================
echo.
echo This will capture all network traffic when you tap "Dash Now"
echo.
echo The script will:
echo   1. Find DasherApp (PID 2344 based on your output)
echo   2. Attach and start monitoring
echo   3. Wait for you to tap "Dash Now"
echo   4. Capture the error details
echo.
echo ================================================================================
echo.

:: Run the monitor
python direct-monitor.py

echo.
echo ================================================================================
echo ANALYZING CAPTURED DATA...
echo ================================================================================
echo.

if exist dasher-capture.log (
    echo Showing ERROR responses:
    echo.
    findstr /C:"ERROR" dasher-capture.log
    echo.
    echo ----------------------------------------
    echo Full log saved in dasher-capture.log
) else (
    echo No capture log found.
)

echo.
pause