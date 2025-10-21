@echo off
cls
color 0A
echo ================================================================================
echo                      DASHER APP FIX - IMMEDIATE SOLUTION
echo ================================================================================
echo.
echo Target: DoorDash DASHER (com.doordash.dasher)
echo.
echo Choose your fix method:
echo.
echo   [1] ANALYTICS FIX (Recommended - Fixes version inconsistency)
echo   [2] COMPREHENSIVE FIX (Heavy spoofing)
echo   [3] LIGHTWEIGHT FIX (Minimal spoofing)
echo   [4] MINIMAL SAFE (If app crashes)
echo   [5] POWERSHELL MENU (All options)
echo.
echo ================================================================================
echo.

set /p choice="Select [1-5]: "

if "%choice%"=="1" goto analytics
if "%choice%"=="2" goto comprehensive
if "%choice%"=="3" goto lightweight
if "%choice%"=="4" goto minimal
if "%choice%"=="5" goto powershell
goto :eof

:analytics
echo.
echo [*] Applying ANALYTICS FIX to DASHER app...
echo [*] This modifies JSON payloads to ensure iOS 17.6.1 everywhere
echo.
python direct-analytics-fix.py
goto :eof

:comprehensive
echo.
echo [*] Applying COMPREHENSIVE FIX to DASHER app...
echo.
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\comprehensive-spoof-stable.js
goto :eof

:lightweight
echo.
echo [*] Applying LIGHTWEIGHT FIX to DASHER app...
echo.
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\lightweight-spoof-only.js
goto :eof

:minimal
echo.
echo [*] Applying MINIMAL SAFE FIX to DASHER app...
echo.
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\doordash-minimal-safe.js
goto :eof

:powershell
echo.
echo [*] Launching PowerShell menu with all options...
echo.
powershell -ExecutionPolicy Bypass -File FridaDasherLauncher.ps1
goto :eof