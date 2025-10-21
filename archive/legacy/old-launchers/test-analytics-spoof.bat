@echo off
chcp 437 >nul 2>&1
cls

echo ================================================================================
echo           DoorDash Analytics-Aware Comprehensive Spoofing Test
echo ================================================================================
echo.
echo This test runs the new analytics-aware spoofing that ensures 100% consistent
echo iOS version reporting across ALL app components.
echo.
echo TARGETS:
echo   - UI APIs (UIDevice, NSProcessInfo)
echo   - System Calls (sysctlbyname, uname)
echo   - Network Headers (User-Agent)
echo   - Analytics JSON Payloads (CRITICAL)
echo.
echo Expected Result: ALL events in HAR file should show iOS 17.6.1
echo ================================================================================
echo.
echo OPTIONS:
echo   [1] Test Analytics Spoofing (Spawn Mode - App Restarts)
echo   [2] Test Analytics Spoofing (Attach Mode - Stay Logged In)
echo   [3] View Instructions for HAR Capture
echo   [Q] Quit
echo.
echo ================================================================================

:menu
set /p choice="Select option [1-3, Q]: "

if /i "%choice%"=="1" goto spawn_test
if /i "%choice%"=="2" goto attach_test
if /i "%choice%"=="3" goto instructions
if /i "%choice%"=="q" goto end
goto menu

:spawn_test
echo.
echo ================================================================================
echo ANALYTICS SPOOFING TEST - SPAWN MODE
echo ================================================================================
echo.
echo Starting DoorDash with comprehensive analytics-aware spoofing...
echo.
echo What this does:
echo   1. Hooks UIDevice and NSProcessInfo for UI consistency
echo   2. Intercepts sysctlbyname for kernel version spoofing
echo   3. Modifies User-Agent headers in all network requests
echo   4. CRITICAL: Intercepts JSON serialization to modify analytics payloads
echo.
echo The app will restart (you'll be logged out).
echo.
pause
python frida-spawn.py doordash.DoorDashConsumer frida-interception-and-unpinning\analytics-comprehensive-spoof.js
echo.
echo ================================================================================
echo TEST COMPLETE - CHECK RESULTS
echo ================================================================================
echo.
echo Please verify:
echo   1. Did you see "JSON serialization hook" in console output?
echo   2. Did you see "Modified analytics key" messages?
echo   3. Capture HAR file and check ALL events for iOS 17.6.1
echo   4. Try to "Dash Now" - should work without API errors
echo.
pause
goto menu

:attach_test
echo.
echo ================================================================================
echo ANALYTICS SPOOFING TEST - ATTACH MODE
echo ================================================================================
echo.
echo NOTE: Make sure DoorDash app is already running and logged in!
echo.
echo First, let's find the DoorDash PID:
python -c "import frida; d = frida.get_usb_device(); processes = d.enumerate_processes(); [print(f'{p.name}:{p.pid}') for p in processes if 'doordash' in p.name.lower() or 'dasher' in p.name.lower()]"
echo.
set /p pid="Enter DoorDash PID: "
if "%pid%"=="" (
    echo [!] No PID provided. Make sure app is running first.
    pause
    goto menu
)
echo.
echo Attaching to PID %pid% with analytics-aware spoofing...
echo.
python frida-attach.py %pid% frida-interception-and-unpinning\analytics-comprehensive-spoof.js
echo.
echo ================================================================================
echo ATTACH TEST COMPLETE
echo ================================================================================
echo.
echo Please verify:
echo   1. Did attach succeed without crashing?
echo   2. Pull to refresh or navigate to activate hooks
echo   3. Check console for "Modified analytics key" messages
echo   4. Capture HAR and verify consistent iOS 17.6.1
echo.
pause
goto menu

:instructions
echo.
echo ================================================================================
echo HOW TO CAPTURE AND VERIFY HAR FILE
echo ================================================================================
echo.
echo 1. BEFORE TESTING:
echo    - Open HTTP Toolkit on your computer
echo    - Ensure it's listening on port 8000
echo    - Clear any previous captured traffic
echo.
echo 2. RUN THE TEST:
echo    - Use option [1] or [2] to start with analytics spoofing
echo    - Wait for app to fully load
echo    - Navigate to the Dash screen
echo.
echo 3. TRIGGER THE ERROR:
echo    - Tap "Dash Now" button
echo    - If error appears, that's OK - we need the HAR
echo    - Try 2-3 times to capture multiple events
echo.
echo 4. SAVE THE HAR:
echo    - In HTTP Toolkit, select all captured requests
echo    - File → Export → HTTP Archive (.har)
echo    - Save with descriptive name (e.g., analytics-test.har)
echo.
echo 5. VERIFY THE FIX:
echo    Search the HAR file for these keys:
echo    - "device_os_version"
echo    - "os_version"
echo    - "ios_version"
echo.
echo    ALL should show "17.6.1" - no "16.3.1" anywhere!
echo.
echo 6. SUCCESS INDICATORS:
echo    - No inconsistent versions in HAR
echo    - Console shows "Modified analytics key" messages
echo    - "Dash Now" works without API errors
echo.
echo ================================================================================
pause
goto menu

:end
echo.
echo ================================================================================
echo NEXT STEPS
echo ================================================================================
echo.
echo 1. If ALL events show iOS 17.6.1:
echo    - The analytics spoofing is working!
echo    - API errors should be resolved
echo    - Update FridaInterceptor.ps1 to use this script
echo.
echo 2. If SOME events still show 16.3.1:
echo    - Check which specific events are not spoofed
echo    - May need additional hooks for those analytics
echo    - Share the HAR file for further analysis
echo.
echo 3. If app crashes:
echo    - The hooks may be too aggressive
echo    - Try disabling Phase 4 (JSON serialization) first
echo    - Then re-enable progressively
echo.
echo Remember: The goal is 100% version consistency across ALL analytics!
echo ================================================================================
pause