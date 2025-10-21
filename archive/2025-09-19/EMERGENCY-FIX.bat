@echo off
cls
echo.
echo =========================================================
echo     EMERGENCY DNS FIX - SSL BYPASS ACTIVATED
echo =========================================================
echo.
echo FIXING: DNS resolution errors (ENOTFOUND)
echo FIXING: SSL pinning bypass failures
echo FIXING: Proxy routing issues
echo.
echo Using selective proxy to prevent DNS breakage
echo.
timeout /t 2 >nul

REM Check if emergency script exists
if not exist "frida-interception-and-unpinning\emergency-fix-ssl-bypass.js" (
    echo [!] Emergency script not found!
    pause
    exit /b 1
)

echo [OK] Emergency fix script ready
echo.
echo Starting FridaInterceptor with EMERGENCY FIX...
echo.
echo IMPORTANT: 
echo - SSL pinning will be bypassed
echo - Proxy will be selective (not for DNS)
echo - Choose option 2 (Spawn mode) for best results
echo.
timeout /t 2 >nul

REM Launch with PowerShell
powershell -ExecutionPolicy Bypass -Command "& { .\FridaInterceptor-Ultimate.ps1; Read-Host 'Press Enter to exit' }"

pause