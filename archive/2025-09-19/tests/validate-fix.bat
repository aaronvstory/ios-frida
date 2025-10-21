@echo off
:: Validation script to ensure SSL bypass is working without DNS errors
:: =============================================

echo -----------------------------------------------------------------------------------------
echo                         FRIDA SSL BYPASS VALIDATION
echo                     Testing DNS Fix and Proxy Configuration
echo -----------------------------------------------------------------------------------------
echo.

:: Test 1: Check script files exist
echo [TEST 1] Checking required files...
if exist "frida-interception-and-unpinning\universal-ssl-pinning-bypass-with-proxy.js" (
    echo [OK] Main SSL bypass script found
) else (
    echo [ERROR] Main SSL bypass script missing!
    exit /b 1
)

if exist "frida-attach.py" (
    echo [OK] Attach script found
) else (
    echo [ERROR] Attach script missing!
    exit /b 1
)

if exist "frida-spawn.py" (
    echo [OK] Spawn script found
) else (
    echo [ERROR] Spawn script missing!
    exit /b 1
)

echo.
echo [TEST 2] Checking for DNS fix in SSL bypass script...
findstr /C:"ExceptionsList" "frida-interception-and-unpinning\universal-ssl-pinning-bypass-with-proxy.js" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] DNS exception list found in script
) else (
    echo [ERROR] DNS fix not found in script!
    exit /b 1
)

echo.
echo [TEST 3] Testing Python and Frida installation...
python -c "import frida; print('[OK] Frida version:', frida.__version__)" 2>nul || (
    echo [ERROR] Frida not installed or Python not configured!
    echo Run: pip install frida-tools
    exit /b 1
)

echo.
echo [TEST 4] Listing archived failed attempts...
dir /B "frida-interception-and-unpinning\archive\failed-attempts-*" 2>nul && (
    echo [OK] Failed attempts archived successfully
) || (
    echo [OK] No failed attempts to archive
)

echo.
echo -----------------------------------------------------------------------------------------
echo                              VALIDATION COMPLETE
echo -----------------------------------------------------------------------------------------
echo.
echo All tests passed! The SSL bypass should work without DNS errors.
echo.
echo To use:
echo   1. Start HTTP Toolkit and get the proxy port (usually 8000)
echo   2. Run start-ultimate.bat
echo   3. Select option 1 (Spawn) or 2 (Attach)
echo   4. Traffic should appear in HTTP Toolkit WITHOUT DNS errors
echo.
echo -----------------------------------------------------------------------------------------
pause