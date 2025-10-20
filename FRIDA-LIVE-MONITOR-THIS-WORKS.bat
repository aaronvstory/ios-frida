@echo off
REM ============================================================================
REM FRIDA LIVE MONITOR - Unified SSH Tunnel + Frida Interception
REM ============================================================================
REM This script bypasses HTTP Toolkit issues by using direct SSH tunnel to
REM iPhone and injecting Frida scripts for live network monitoring.
REM
REM Prerequisites:
REM   1. 3uTools SSH tunnel already opened (127.0.0.1:10022 -> iPhone:22)
REM   2. HTTP Toolkit running on 192.168.50.9:8000
REM   3. Frida server running on iPhone (frida-server &)
REM   4. DoorDash Dasher app installed
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo    FRIDA LIVE MONITOR - Direct SSH Tunnel Mode
echo ============================================================
echo.

REM Load configuration
set CONFIG_FILE=config\frida-config.json
if not exist "%CONFIG_FILE%" (
    echo [ERROR] Configuration file not found: %CONFIG_FILE%
    pause
    exit /b 1
)

REM Set default values (will be overridden if config is parsed correctly)
set IPHONE_IP=192.168.50.130
set PROXY_HOST=192.168.50.9
set PROXY_PORT=8000
set SSH_PORT=22
set BUNDLE_ID=com.doordash.dasher
set APP_NAME=DoorDash Dasher

echo [1/6] Configuration
echo   iPhone IP: %IPHONE_IP%
echo   Proxy: %PROXY_HOST%:%PROXY_PORT%
echo   SSH Port: %SSH_PORT% (via 3uTools tunnel)
echo   App: %APP_NAME% (%BUNDLE_ID%)
echo.

REM ============================================================================
REM Step 2: Test SSH connection
REM ============================================================================
echo [2/6] Testing SSH Connection...
plink.exe -P %SSH_PORT% root@127.0.0.1 -pw alpine "echo SSH connection successful" 2>nul
if errorlevel 1 (
    echo [WARNING] SSH connection failed. Make sure 3uTools tunnel is open!
    echo.
    echo Expected: 3uTools shows "Succeeded to open SSH tunnel" at 127.0.0.1
    echo.
    choice /C YN /M "Continue anyway? (Y/N)"
    if errorlevel 2 exit /b 1
) else (
    echo [SUCCESS] SSH connection verified
)
echo.

REM ============================================================================
REM Step 3: Check Frida server on device
REM ============================================================================
echo [3/6] Checking Frida Server...
plink.exe -P %SSH_PORT% root@127.0.0.1 -pw alpine "ps aux | grep frida-server | grep -v grep" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Frida server not running. Starting it...
    plink.exe -P %SSH_PORT% root@127.0.0.1 -pw alpine "nohup /usr/sbin/frida-server > /dev/null 2>&1 &"
    timeout /t 2 /nobreak >nul
    echo [SUCCESS] Frida server started
) else (
    echo [SUCCESS] Frida server already running
)
echo.

REM ============================================================================
REM Step 4: Choose monitoring mode
REM ============================================================================
echo [4/6] Select Monitoring Mode:
echo.
echo   1. SPAWN MODE (Recommended)
echo      - Restarts the app (you'll be logged out)
echo      - Best for reliable traffic capture
echo      - Uses enhanced proxy script (no errors)
echo.
echo   2. ATTACH MODE (Stay Logged In)
echo      - Attaches to running app
echo      - Keeps your session alive
echo      - May need to refresh app to activate proxy
echo.
choice /C 12 /N /M "Enter choice (1 or 2): "
set MODE_CHOICE=%errorlevel%
echo.

if %MODE_CHOICE%==1 (
    set MODE=spawn
    set SCRIPT_PATH=frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js
    set MODE_NAME=SPAWN MODE
    echo [SELECTED] SPAWN MODE - App will restart
) else (
    set MODE=attach
    set SCRIPT_PATH=frida-interception-and-unpinning\attach-mode-proxy.js
    set MODE_NAME=ATTACH MODE
    echo [SELECTED] ATTACH MODE - Will attach to running app
    echo.
    echo [ACTION REQUIRED] Make sure Dasher app is already running!
    pause
)
echo.

REM Verify script exists
if not exist "%SCRIPT_PATH%" (
    echo [ERROR] Frida script not found: %SCRIPT_PATH%
    pause
    exit /b 1
)
echo [INFO] Using script: %SCRIPT_PATH%
echo.

REM ============================================================================
REM Step 5: Launch Frida with appropriate mode
REM ============================================================================
echo [5/6] Launching Frida in %MODE_NAME%...
echo.
echo ============================================================
echo    LIVE MONITORING ACTIVE - Press Ctrl+C to stop
echo ============================================================
echo.
echo [TIP] Watch for these messages:
echo   [+] Configuring proxy for defaultSessionConfiguration
echo   [+] Proxy configured: %PROXY_HOST%:%PROXY_PORT%
echo   [+] Bypassing SSL pinning...
echo.
echo [TIP] Traffic should appear in HTTP Toolkit at:
echo   http://%PROXY_HOST%:%PROXY_PORT%
echo.
echo ============================================================
echo.

if "%MODE%"=="spawn" (
    REM Spawn mode - restart app
    python frida-spawn.py %BUNDLE_ID% "%SCRIPT_PATH%"
) else (
    REM Attach mode - get PID first
    echo [INFO] Finding %APP_NAME% process...

    REM Use frida-ps to get the PID
    for /f "tokens=1" %%i in ('frida-ps -Uai ^| findstr /C:"%BUNDLE_ID%"') do set APP_PID=%%i

    if not defined APP_PID (
        echo [ERROR] %APP_NAME% is not running!
        echo.
        echo Please:
        echo   1. Open the Dasher app on your iPhone
        echo   2. Log in if needed
        echo   3. Run this script again
        pause
        exit /b 1
    )

    echo [SUCCESS] Found %APP_NAME% with PID: %APP_PID%
    echo.
    python frida-attach.py %APP_PID% "%SCRIPT_PATH%"
)

REM ============================================================================
REM Step 6: Cleanup on exit
REM ============================================================================
echo.
echo [6/6] Monitoring session ended
echo.
echo ============================================================
echo    NEXT STEPS FOR LIVE MANIPULATION
echo ============================================================
echo.
echo To observe and manipulate traffic in real-time:
echo.
echo 1. HTTP Toolkit should show captured requests
echo 2. You can modify requests/responses in HTTP Toolkit UI
echo 3. Set breakpoints on specific endpoints
echo 4. Rewrite headers, body content, status codes
echo.
echo For advanced manipulation, you can:
echo   - Edit the JS script in: %SCRIPT_PATH%
echo   - Add custom Interceptor.attach() hooks
echo   - Log request/response bodies
echo   - Modify data before sending
echo.
echo ============================================================
echo.
pause
