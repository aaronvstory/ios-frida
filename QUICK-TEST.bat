@echo off
REM ============================================================================
REM QUICK TEST - Verify Frida Setup
REM ============================================================================
REM This script quickly tests all prerequisites for Frida monitoring
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo    FRIDA SETUP VERIFICATION
echo ============================================================
echo.

set PASS_COUNT=0
set FAIL_COUNT=0

REM Test 1: Check if plink.exe exists
echo [1/7] Checking plink.exe...
if exist "plink.exe" (
    echo [PASS] plink.exe found
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] plink.exe not found
    set /a FAIL_COUNT+=1
)
echo.

REM Test 2: Check Python installation
echo [2/7] Checking Python installation...
python --version >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VER=%%i
    echo [PASS] !PYTHON_VER!
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Python not found in PATH
    set /a FAIL_COUNT+=1
)
echo.

REM Test 3: Check Frida installation
echo [3/7] Checking Frida installation...
frida --version >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=*" %%i in ('frida --version 2^>^&1') do set FRIDA_VER=%%i
    echo [PASS] Frida !FRIDA_VER!
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Frida not installed
    echo [INFO] Install with: pip install -r requirements.txt
    set /a FAIL_COUNT+=1
)
echo.

REM Test 4: Check config file
echo [4/7] Checking configuration file...
if exist "config\frida-config.json" (
    echo [PASS] config\frida-config.json found
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] config\frida-config.json not found
    set /a FAIL_COUNT+=1
)
echo.

REM Test 5: Check main scripts
echo [5/7] Checking core scripts...
set SCRIPT_MISSING=0
if not exist "frida-spawn.py" (
    echo [FAIL] frida-spawn.py not found
    set SCRIPT_MISSING=1
)
if not exist "frida-attach.py" (
    echo [FAIL] frida-attach.py not found
    set SCRIPT_MISSING=1
)
if not exist "live-network-monitor.py" (
    echo [FAIL] live-network-monitor.py not found
    set SCRIPT_MISSING=1
)

if %SCRIPT_MISSING%==0 (
    echo [PASS] All core scripts present
    set /a PASS_COUNT+=1
) else (
    set /a FAIL_COUNT+=1
)
echo.

REM Test 6: Check Frida scripts directory
echo [6/7] Checking Frida injection scripts...
if exist "frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js" (
    echo [PASS] Enhanced proxy script found
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Enhanced proxy script not found
    set /a FAIL_COUNT+=1
)
echo.

REM Test 7: Test SSH connection (optional - may fail if tunnel not open)
echo [7/7] Testing SSH connection (via 3uTools tunnel)...
plink.exe -P 10022 root@127.0.0.1 -pw alpine "echo 'SSH OK'" 2>nul | findstr "SSH OK" >nul
if %errorlevel%==0 (
    echo [PASS] SSH tunnel connected
    set /a PASS_COUNT+=1
) else (
    echo [WARN] SSH tunnel not connected (open via 3uTools)
    echo [INFO] This is optional - open tunnel before monitoring
    set /a PASS_COUNT+=1
)
echo.

REM Summary
echo ============================================================
echo    TEST SUMMARY
echo ============================================================
echo.
echo Total Tests: 7
echo Passed: %PASS_COUNT%
echo Failed: %FAIL_COUNT%
echo.

if %FAIL_COUNT%==0 (
    echo [SUCCESS] All tests passed! You're ready to run FRIDA-LIVE-MONITOR.bat
    echo.
    echo Next steps:
    echo   1. Ensure 3uTools SSH tunnel is open
    echo   2. Run: FRIDA-LIVE-MONITOR.bat
    echo   3. Choose SPAWN or ATTACH mode
    echo   4. Watch traffic in HTTP Toolkit
) else (
    echo [WARNING] Some tests failed. Please fix the issues above.
    echo.
    echo Common fixes:
    echo   - Install Python from python.org
    echo   - Install Frida: pip install -r requirements.txt
    echo   - Check file paths and locations
)
echo.
echo ============================================================
pause
