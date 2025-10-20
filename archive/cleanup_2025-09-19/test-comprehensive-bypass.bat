@echo off
:: Test the comprehensive SSL pinning bypass
:: =============================================

echo -----------------------------------------------------------------------------------------
echo                    TESTING COMPREHENSIVE SSL BYPASS
echo -----------------------------------------------------------------------------------------
echo.

echo [*] Using comprehensive-ssl-pinning-bypass.js which includes:
echo     - SecTrustEvaluate bypass
echo     - SecTrustEvaluateWithError bypass  
echo     - NSURLSession delegate bypasses
echo     - AFNetworking bypass
echo     - TrustKit bypass
echo     - Alamofire bypass
echo     - Custom certificate validation bypass
echo     - Proxy configuration with DNS exceptions
echo.
echo -----------------------------------------------------------------------------------------
echo.

:: Test with Python directly
echo [*] Testing with frida-spawn.py...
python frida-spawn.py doordash.DoorDashConsumer frida-interception-and-unpinning\comprehensive-ssl-pinning-bypass.js

echo.
echo -----------------------------------------------------------------------------------------
echo If you're still seeing pinning errors, check:
echo   1. HTTP Toolkit is running and proxy port is 8000
echo   2. Your computer IP is correct in the script (currently 192.168.50.9)
echo   3. iPhone and computer are on same network
echo   4. Frida server is running on iPhone
echo -----------------------------------------------------------------------------------------
pause