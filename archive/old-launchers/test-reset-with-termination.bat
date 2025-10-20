@echo off
echo =========================================
echo  TESTING ENHANCED RESET WITH TERMINATION
echo =========================================
echo.
echo This will test the reset function with app termination
echo.
echo Expected behavior:
echo   1. Hooks will be removed
echo   2. Proxy will be cleared
echo   3. App will be FORCE TERMINATED
echo   4. Complete reset achieved
echo.
echo =========================================
echo.
powershell -ExecutionPolicy Bypass -File FridaInterceptor.ps1
pause