@echo off
cls
echo ================================================================================
echo                    JAILBREAK DETECTION BYPASS
echo ================================================================================
echo.
echo The REAL issue: DoorDash has flagged your account/device!
echo.
echo This bypass:
echo   - Hides ALL jailbreak indicators
echo   - Blocks file system checks
echo   - Hides Frida and tweaks
echo   - Spoofs sandbox integrity
echo   - Enhances app attestation
echo.
echo IMPORTANT STEPS:
echo   1. Run this script
echo   2. LOG OUT of the app
echo   3. LOG BACK IN with your credentials
echo   4. Try "Dash Now" again
echo.
echo ================================================================================
echo.

python frida-spawn.py com.doordash.dasher jailbreak-bypass.js

echo.
echo ================================================================================
echo Remember: LOG OUT and LOG BACK IN for this to work!
echo ================================================================================
pause