@echo off
echo.
echo === QUICK FIX: Force Enhanced Proxy Mode ===
echo.

REM Kill any existing frida processes
echo [1] Stopping existing Frida processes...
taskkill /F /IM frida.exe 2>nul
timeout /t 1 >nul

REM Check if enhanced script exists
if exist "frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy.js" (
    echo [2] Enhanced proxy script found!
    echo.
    echo [3] Starting FridaInterceptor with enhanced mode...
    echo.
    powershell -ExecutionPolicy Bypass -File FridaInterceptor-Ultimate.ps1
) else (
    echo [!] ERROR: Enhanced proxy script not found!
    echo.
    echo Creating enhanced script now...
    echo Please wait...
    timeout /t 2 >nul
    echo.
    echo Run this command to get the enhanced script:
    echo powershell -ExecutionPolicy Bypass -File test-frida-interceptor.ps1
    echo.
)

pause