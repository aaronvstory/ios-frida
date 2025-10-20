@echo off
cls
echo ================================================================================
echo                     403 ERROR FIX FOR DASHER APP
echo ================================================================================
echo.
echo Based on the captured logs, the error is:
echo   - Endpoint: /v1/dashes/
echo   - Status: 403 Forbidden
echo   - Message: "System error, please log out and log back in"
echo.
echo This fix intercepts that specific request and returns a success response.
echo.
echo Choose mode:
echo   [1] SPAWN mode (App restarts - clean start)
echo   [2] ATTACH mode (Stay logged in)
echo.
set /p choice="Enter 1 or 2: "

if "%choice%"=="1" (
    echo.
    echo Starting SPAWN mode with 403 fix...
    echo.
    python frida-spawn.py com.doordash.dasher fix-403-error.js
) else (
    echo.
    echo Starting ATTACH mode with 403 fix...
    echo First, finding DasherApp PID:
    echo.
    python -c "import frida; d = frida.get_usb_device(); [print(f'{p.name}: {p.pid}') for p in d.enumerate_processes() if 'dash' in p.name.lower()]"
    echo.
    set /p pid="Enter DasherApp PID: "
    python frida-attach.py %pid% fix-403-error.js
)

echo.
echo ================================================================================
echo Fix applied. Try tapping "Schedule/Dash Now" again.
echo ================================================================================
pause