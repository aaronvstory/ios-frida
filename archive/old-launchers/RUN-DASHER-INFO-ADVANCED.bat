@echo off
cls
echo ================================================================================
echo                  ADVANCED DASHER ACCOUNT INFORMATION EXTRACTOR
echo ================================================================================
echo.
echo This tool extracts complete dasher account information including:
echo.
echo   [+] Dasher name, ID, email, phone
echo   [+] Account status (active, suspended, restricted, DEACTIVATED)
echo   [+] BAN NOTES - Shows if account is DEACTIVATED and why
echo   [+] Fraud/Trust/Safety actions taken
echo   [+] Location and market information
echo   [+] Vehicle details and ratings
echo.
echo IMPROVEMENTS IN THIS VERSION:
echo ------------------------------
echo   - Waits 10 seconds for app to fully load
echo   - Monitors for 60 seconds total
echo   - Only captures MAIN profile endpoint (not sub-endpoints)
echo   - Shows real-time monitoring status
echo   - Better field detection and parsing
echo.
echo ================================================================================
echo.

:: Create ban-notes directory if it doesn't exist
if not exist "ban-notes" (
    echo Creating ban-notes directory...
    mkdir ban-notes
    echo.
)

echo Choose extraction mode:
echo [1] SPAWN mode - App restarts (logs you out)
echo [2] ATTACH mode - Keep logged in (for already running app)
echo.
set /p mode="Enter choice (1 or 2): "

echo.

if "%mode%"=="2" (
    echo ATTACH MODE - Finding running DoorDash Dasher app...
    echo.

    :: Use frida-ps to find the PID
    for /f "tokens=1,2" %%a in ('frida-ps -U ^| findstr "dasher"') do (
        set PID=%%a
        set NAME=%%b
    )

    if defined PID (
        echo Found: PID %PID% - %NAME%
        echo.
        echo Starting extraction in ATTACH mode...
        python frida-attach.py %PID% dasher-info-advanced.js
    ) else (
        echo ERROR: DoorDash Dasher app not running!
        echo Please open the app first, then run this script with option 2.
    )
) else (
    echo SPAWN MODE - Restarting app...
    echo.
    python frida-spawn.py com.doordash.dasher dasher-info-advanced.js
)

echo.
echo ================================================================================
echo.
echo IMPORTANT STEPS:
echo   1. Script will wait 10 seconds for app to load
echo   2. Navigate to Account/Profile section in the app
echo   3. Pull down to refresh
echo   4. Look for "PROFILE DATA CAPTURED!" message
echo.
echo The script will monitor for 60 seconds total.
echo.
echo Log files saved in: ban-notes\[DasherName]_[Timestamp].log
echo.
echo ================================================================================
pause