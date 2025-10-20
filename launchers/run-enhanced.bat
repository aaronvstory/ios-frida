@echo off
cls
echo.
echo =========================================================
echo     FRIDA ENHANCED PROXY MODE - HTTP Toolkit Fix
echo =========================================================
echo.
echo This will ensure HTTP Toolkit shows all traffic
echo.

REM Check if enhanced script exists
if not exist "frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy.js" (
    echo [!] Enhanced script missing - Cannot continue!
    echo.
    echo Please run: test-frida-interceptor.ps1
    echo.
    pause
    exit /b 1
)

echo [OK] Enhanced proxy script found
echo.
echo Starting FridaInterceptor with ENHANCED proxy mode...
echo.
echo IMPORTANT: When prompted, choose option 5 (DoorDash Customer - Attach)
echo.
timeout /t 2 >nul

REM Launch with PowerShell
powershell -ExecutionPolicy Bypass -Command "& { .\FridaInterceptor-Ultimate.ps1; Read-Host 'Press Enter to exit' }"

pause