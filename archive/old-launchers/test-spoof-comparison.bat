@echo off
chcp 437 >nul 2>&1
cls

echo ================================================================================
echo           DoorDash Spoofing Comparison Test
echo ================================================================================
echo.
echo This script helps you test different spoofing approaches to fix the
echo "ErrorNetworking.ResponseStatusCodeError error 1" issue.
echo.
echo Available spoofing modes:
echo   [1] Lightweight Spoof (proven stable, minimal hooks)
echo   [2] Comprehensive Spoof (enhanced device fingerprinting)
echo   [3] Comprehensive Attach (stay logged in)
echo   [Q] Quit
echo.
echo ================================================================================

:menu
set /p choice="Select spoofing mode [1-3, Q]: "

if /i "%choice%"=="1" goto lightweight
if /i "%choice%"=="2" goto comprehensive
if /i "%choice%"=="3" goto attach
if /i "%choice%"=="q" goto end
goto menu

:lightweight
echo.
echo [+] Testing LIGHTWEIGHT spoofing (minimal hooks)...
echo     - iOS 17.6.1, CFNetwork 1490.0.4
echo     - Basic User-Agent spoofing
echo     - Proven stable, no crashes
echo.
python frida-spawn.py doordash.DoorDashConsumer frida-interception-and-unpinning\lightweight-spoof-only.js
goto end

:comprehensive
echo.
echo [+] Testing COMPREHENSIVE spoofing (enhanced fingerprinting)...
echo     - iPhone 14 Pro device model
echo     - Hardware model strings (iPhone15,3)
echo     - Anti-jailbreak detection
echo     - Enhanced User-Agent + system info
echo.
python frida-spawn.py doordash.DoorDashConsumer frida-interception-and-unpinning\comprehensive-spoof-stable.js
goto end

:attach
echo.
echo [+] Testing COMPREHENSIVE ATTACH mode (stay logged in)...
echo     - Same enhanced spoofing as #2
echo     - Preserves existing login session
echo     - Pull to refresh to activate proxy
echo.
echo [?] First, get the DoorDash PID by running the main script option [L]
set /p pid="Enter DoorDash PID (or press Enter to skip): "
if "%pid%"=="" (
    echo [!] No PID provided. Run FridaInterceptor-Ultimate.ps1 and use option [L] first.
    pause
    goto end
)
python frida-attach.py %pid% frida-interception-and-unpinning\comprehensive-spoof-attach.js
goto end

:end
echo.
echo ================================================================================
echo Test Results Analysis:
echo.
echo 1. Check HTTP Toolkit for traffic capture
echo 2. Try to start a dash in the DoorDash app
echo 3. Look for the error message:
echo    - Still getting "ErrorNetworking.ResponseStatusCodeError error 1"?
echo    - Any crashes or app freezing?
echo    - Traffic appearing in HTTP Toolkit?
echo.
echo If comprehensive spoofing fixes the API error, we've identified the issue
echo as insufficient device fingerprinting in the lightweight version.
echo ================================================================================
pause