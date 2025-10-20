@echo off
cls
echo ================================================================================
echo                          ULTIMATE DASHER MONITOR
echo ================================================================================
echo.
echo This will capture EVERYTHING when you tap "Dash Now"
echo.
echo Choose mode:
echo   [1] SPAWN mode (App restarts - most reliable)
echo   [2] ATTACH mode (Stay logged in)
echo.
set /p choice="Enter 1 or 2: "

if "%choice%"=="1" (
    echo.
    echo Starting SPAWN mode - app will restart...
    echo.
    python frida-spawn.py com.doordash.dasher ultimate-monitor.js
) else (
    echo.
    echo Starting ATTACH mode...
    echo First, let's find the Dasher PID:
    echo.
    python -c "import frida; d = frida.get_usb_device(); [print(f'{p.name}: {p.pid}') for p in d.enumerate_processes() if 'dash' in p.name.lower()]"
    echo.
    set /p pid="Enter DasherApp PID: "
    python frida-attach.py %pid% ultimate-monitor.js
)

echo.
echo ================================================================================
echo Monitor session ended. Check console output above for errors.
echo ================================================================================
pause