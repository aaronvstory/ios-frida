@echo off
cls
echo.
echo =========================================================
echo     FIXED SSL BYPASS - NO MORE DNS ERRORS!
echo =========================================================
echo.
echo This uses the WORKING scripts that:
echo  - Bypass SSL certificate pinning
echo  - Route traffic to HTTP Toolkit (optional)
echo  - DO NOT break DNS resolution
echo.
echo Select your preference:
echo.
echo [1] With HTTP Toolkit (see traffic)
echo [2] Without HTTP Toolkit (just bypass SSL)
echo.
choice /C 12 /N /M "Enter selection (1 or 2): "

if %errorlevel%==2 goto :noProxy
if %errorlevel%==1 goto :withProxy

:withProxy
echo.
echo Using: WORKING-ssl-bypass-with-proxy.js
echo.
echo Starting with HTTP Toolkit proxy enabled...
echo Traffic will appear at 192.168.50.9:8000
echo.
goto :run

:noProxy
echo.
echo Using: WORKING-ssl-bypass.js
echo.
echo Starting with SSL bypass only (no proxy)...
echo.
goto :run

:run
echo Running FridaInterceptor with WORKING scripts...
echo.
powershell -ExecutionPolicy Bypass -File "FridaInterceptor-Ultimate.ps1"

pause