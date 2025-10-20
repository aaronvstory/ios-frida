@echo off
cls
echo.
echo =========================================================
echo     TESTING BOTH MODES - Spawn vs Attach
echo =========================================================
echo.
echo This will help determine which mode works best
echo.
echo [1] Test SPAWN mode (App restarts, logs you out)
echo     - Uses fixed enhanced script (no errors)
echo     - Fresh network sessions
echo     - Most reliable for proxy routing
echo.
echo [2] Test ATTACH mode (Stay logged in)
echo     - Uses attach-optimized script
echo     - Modifies existing sessions
echo     - May need app refresh to activate
echo.
echo Which mode to test?
choice /C 12Q /N /M "Enter selection (1=Spawn, 2=Attach, Q=Quit): "

if %errorlevel%==3 goto :quit
if %errorlevel%==2 goto :attach
if %errorlevel%==1 goto :spawn

:spawn
echo.
echo Starting SPAWN mode test...
echo.
echo IMPORTANT: App will restart and log you out
echo.
timeout /t 2 >nul
powershell -ExecutionPolicy Bypass -Command "& { .\FridaInterceptor-Ultimate.ps1 }"
goto :end

:attach
echo.
echo Starting ATTACH mode test...
echo.
echo IMPORTANT: After attaching, you may need to:
echo   1. Pull down to refresh the app
echo   2. Navigate to a new screen
echo   3. Trigger any network activity
echo.
timeout /t 2 >nul
powershell -ExecutionPolicy Bypass -Command "& { .\FridaInterceptor-Ultimate.ps1 }"
goto :end

:quit
echo.
echo Cancelled.
goto :end

:end
pause