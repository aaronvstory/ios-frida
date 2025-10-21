@echo off
cls
echo.
echo =========================================================
echo     RESTORED TO ORIGINAL WORKING CONFIGURATION
echo =========================================================
echo.
echo This uses the EXACT configuration that was working before:
echo  - universal-ssl-pinning-bypass-with-proxy.js
echo  - Simple proxy setup (not enhanced)
echo  - No DNS issues
echo.
echo Starting with ORIGINAL working scripts...
echo.
timeout /t 2 >nul

REM Launch with PowerShell
powershell -ExecutionPolicy Bypass -File "FridaInterceptor-Ultimate.ps1"

pause