@echo off
chcp 437 >nul 2>&1
cls

echo ================================================================================
echo           DoorDash Comprehensive Spoofing Test
echo ================================================================================
echo.
echo This script tests the new comprehensive spoofing with enhanced device fingerprinting
echo that should address the "ErrorNetworking.ResponseStatusCodeError error 1" issue.
echo.
echo Enhanced features:
echo   - Device model spoofing (iPhone 14 Pro)
echo   - Hardware model strings (iPhone15,3)
echo   - Kernel version consistency
echo   - Anti-jailbreak detection
echo   - Enhanced User-Agent spoofing
echo   - System capability spoofing
echo.
echo ================================================================================

echo [+] Testing comprehensive spoofing with DoorDash Dasher app...
echo.
echo Starting Frida with comprehensive-spoof-stable.js...
python frida-spawn.py doordash.DoorDashConsumer frida-interception-and-unpinning\comprehensive-spoof-stable.js

echo.
echo ================================================================================
echo Test completed. Check HTTP Toolkit for traffic and try starting a dash.
echo ================================================================================
pause