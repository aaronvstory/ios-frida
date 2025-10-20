@echo off
chcp 437 >nul 2>&1
cls

echo ================================================================================
echo           DoorDash API Error Fix Test Suite
echo ================================================================================
echo.
echo This test suite helps fix "ErrorNetworking.ResponseStatusCodeError error 1"
echo by progressively testing different spoofing approaches.
echo.
echo PROBLEM: DoorDash app no longer crashes but gets API validation errors
echo SOLUTION: Enhanced device fingerprinting to bypass server-side detection
echo.
echo ================================================================================
echo.
echo TEST PROGRESSION:
echo   [1] Test Lightweight (current working - no crashes)
echo   [2] Test Comprehensive (enhanced fingerprinting - spawn mode)
echo   [3] Test Comprehensive (enhanced fingerprinting - attach mode)
echo   [4] Compare Results
echo   [Q] Quit
echo.
echo ================================================================================

:menu
set /p choice="Select test [1-4, Q]: "

if /i "%choice%"=="1" goto test_lightweight
if /i "%choice%"=="2" goto test_comprehensive
if /i "%choice%"=="3" goto test_attach
if /i "%choice%"=="4" goto compare
if /i "%choice%"=="q" goto end
goto menu

:test_lightweight
echo.
echo ================================================================================
echo TEST 1: LIGHTWEIGHT SPOOFING (Current Baseline)
echo ================================================================================
echo.
echo What this tests:
echo   - Basic iOS version spoofing (17.6.1)
echo   - CFNetwork version spoofing (1490.0.4)
echo   - Simple User-Agent modification
echo   - Basic proxy configuration
echo.
echo Expected result: App starts without crashing, proxy works, but API error persists
echo.
pause
python frida-spawn.py doordash.DoorDashConsumer frida-interception-and-unpinning\lightweight-spoof-only.js
echo.
echo ================================================================================
echo LIGHTWEIGHT TEST COMPLETED
echo.
echo Please check:
echo   1. Did the app start without crashing? (Should be YES)
echo   2. Is traffic appearing in HTTP Toolkit? (Should be YES)
echo   3. Can you try to start a dash? (Will likely get error)
echo   4. Error message: "ErrorNetworking.ResponseStatusCodeError error 1"?
echo.
pause
goto menu

:test_comprehensive
echo.
echo ================================================================================
echo TEST 2: COMPREHENSIVE SPOOFING (Enhanced Fingerprinting - SPAWN)
echo ================================================================================
echo.
echo What this adds:
echo   - Device model spoofing (iPhone 14 Pro / iPhone15,3)
echo   - Hardware model strings and capabilities
echo   - Kernel version consistency
echo   - Enhanced User-Agent with complete device info
echo   - Basic anti-jailbreak detection bypass
echo   - System capability spoofing
echo.
echo Expected result: Should fix API validation errors while maintaining stability
echo.
pause
python frida-spawn.py doordash.DoorDashConsumer frida-interception-and-unpinning\comprehensive-spoof-stable.js
echo.
echo ================================================================================
echo COMPREHENSIVE SPAWN TEST COMPLETED
echo.
echo Please check:
echo   1. Did the app start without crashing? (Should be YES)
echo   2. Is traffic appearing in HTTP Toolkit? (Should be YES)
echo   3. Can you try to start a dash? (SHOULD WORK if fix is successful)
echo   4. Any "ErrorNetworking.ResponseStatusCodeError" errors? (Should be NO)
echo.
pause
goto menu

:test_attach
echo.
echo ================================================================================
echo TEST 3: COMPREHENSIVE SPOOFING (Enhanced Fingerprinting - ATTACH)
echo ================================================================================
echo.
echo What this tests:
echo   - Same enhanced spoofing as Test 2
echo   - Attach mode (preserves login session)
echo   - Optimized for running apps
echo.
echo NOTE: Make sure DoorDash app is already running and logged in
echo.
echo First, get the DoorDash PID:
python -c "import frida; d = frida.get_usb_device(); processes = d.enumerate_processes(); [print(f'{p.name}:{p.pid}') for p in processes if 'doordash' in p.name.lower() or 'dasher' in p.name.lower()]"
echo.
set /p pid="Enter DoorDash PID (or press Enter to skip): "
if "%pid%"=="" (
    echo [!] No PID provided. Make sure app is running first.
    goto menu
)
echo.
echo Attaching to PID %pid%...
python frida-attach.py %pid% frida-interception-and-unpinning\comprehensive-spoof-attach.js
echo.
echo ================================================================================
echo COMPREHENSIVE ATTACH TEST COMPLETED
echo.
echo Please check:
echo   1. Did the attach succeed without app crash? (Should be YES)
echo   2. Pull to refresh or navigate to activate proxy
echo   3. Is traffic appearing in HTTP Toolkit? (Should be YES after refresh)
echo   4. Can you try to start a dash? (SHOULD WORK if fix is successful)
echo   5. Any "ErrorNetworking.ResponseStatusCodeError" errors? (Should be NO)
echo.
pause
goto menu

:compare
echo.
echo ================================================================================
echo TEST RESULTS COMPARISON
echo ================================================================================
echo.
echo Please fill out this comparison based on your testing:
echo.
echo TEST 1 - LIGHTWEIGHT (Baseline):
echo   App Crashes: [Should be NO]
echo   Proxy Works: [Should be YES]
echo   API Error: [Should be YES - "ErrorNetworking.ResponseStatusCodeError error 1"]
echo   Can Start Dash: [Should be NO]
echo.
echo TEST 2 - COMPREHENSIVE SPAWN:
echo   App Crashes: [  ]
echo   Proxy Works: [  ]
echo   API Error: [  ]
echo   Can Start Dash: [  ]
echo.
echo TEST 3 - COMPREHENSIVE ATTACH:
echo   App Crashes: [  ]
echo   Proxy Works: [  ]
echo   API Error: [  ]
echo   Can Start Dash: [  ]
echo.
echo ================================================================================
echo ANALYSIS:
echo.
echo If comprehensive mode fixes the API error:
echo   - The issue was insufficient device fingerprinting
echo   - DoorDash validates device model, hardware info, etc.
echo   - The enhanced spoofing bypasses their server-side validation
echo.
echo If comprehensive mode still has API errors:
echo   - May need to analyze specific headers/values DoorDash checks
echo   - Could be additional anti-tampering detection
echo   - May need to adjust spoofed values or add more hooks
echo.
echo If comprehensive mode causes crashes:
echo   - The enhanced hooks are too aggressive
echo   - Need to dial back to more minimal approach
echo   - May need to test individual hook categories
echo.
echo ================================================================================
pause
goto menu

:end
echo.
echo ================================================================================
echo NEXT STEPS:
echo.
echo If comprehensive spoofing fixed the API error:
echo   1. Use options [5] or [6] in the main FridaInterceptor menu
echo   2. This is now your primary method for DoorDash
echo   3. The enhanced fingerprinting bypassed their validation
echo.
echo If API error persists:
echo   1. Capture network traffic in HTTP Toolkit
echo   2. Look for specific headers/values being rejected
echo   3. May need to analyze DoorDash's validation logic further
echo   4. Consider additional spoofing (certificates, capabilities, etc.)
echo.
echo If crashes occur:
echo   1. Revert to lightweight mode for stability
echo   2. Test individual hooks to find problematic ones
echo   3. Create a middle-ground approach with fewer hooks
echo.
echo The key insight: API errors mean the proxy/injection works,
echo but the server is detecting modified/spoofed values.
echo ================================================================================
pause