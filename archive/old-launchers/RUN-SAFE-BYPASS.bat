@echo off
cls
echo ================================================================================
echo                    MINIMAL SAFE BYPASS (NO CRASH)
echo ================================================================================
echo.
echo This minimal version:
echo   - ONLY intercepts the specific /v1/dashes/ endpoint
echo   - ONLY modifies 403 responses
echo   - Returns valid empty array []
echo   - No alert hooks (to avoid crashes)
echo   - No error prevention (to avoid crashes)
echo.
echo Much safer - should not crash the app.
echo.
echo ================================================================================
echo.

python frida-spawn.py com.doordash.dasher minimal-safe-bypass.js

echo.
echo ================================================================================
echo If app doesn't crash, try "Schedule/Dash Now"
echo ================================================================================
pause