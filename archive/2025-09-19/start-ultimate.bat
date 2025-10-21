@echo off
:: FridaInterceptor Ultimate - Main Launcher
:: Features: Spawn/Attach modes, Bundle ID display, Stay logged in
:: =============================================

title FridaInterceptor Ultimate

cls

echo -----------------------------------------------------------------------------------------
echo                         FRIDA INTERCEPTOR ULTIMATE
echo                     iOS HTTP Toolkit Bypass with SSL Unpinning
echo -----------------------------------------------------------------------------------------
echo.

:: Launch the PowerShell script
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0FridaInterceptor-Ultimate.ps1" %*

:: Check for errors
if %errorlevel% neq 0 (
    echo.
    echo -----------------------------------------------------------------------------------------
    echo Process ended. Press any key to exit...
    pause >nul
)

exit /b