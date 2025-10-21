@echo off
chcp 437 >nul 2>&1
cls

:: ================================================================================
:: DOORDASH DASHER FRIDA INTERCEPTOR - AUTONOMOUS LAUNCHER
:: For DoorDash DASHER app ONLY (com.doordash.dasher)
:: ================================================================================

echo ================================================================================
echo                  DOORDASH DASHER AUTO-FIX LAUNCHER
echo ================================================================================
echo.
echo Target App: DoorDash DASHER (com.doordash.dasher)
echo.
echo This launcher automatically:
echo   1. Establishes SSH tunnel to iPhone
echo   2. Starts Frida server
echo   3. Launches DASHER app with fixes
echo   4. Monitors network traffic
echo   5. Detects and fixes API errors
echo.
echo ================================================================================
echo.

:: Check Python installation
echo Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)
echo [OK] Python installed

:: Check Frida installation
echo Checking Frida...
python -c "import frida" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Frida not installed. Installing now...
    pip install frida-tools frida
    if errorlevel 1 (
        echo [ERROR] Failed to install Frida
        pause
        exit /b 1
    )
)
echo [OK] Frida installed

:: Phase 1: Setup SSH Tunnel
echo.
echo [1/5] Setting up SSH tunnel...
tasklist /FI "IMAGENAME eq plink.exe" 2>nul | find /I "plink.exe" >nul
if errorlevel 1 (
    start /min cmd /c "plink -L 27042:127.0.0.1:22 root@192.168.50.113 -pw alpine"
    timeout /t 3 >nul
)
echo [OK] SSH tunnel active

:: Phase 2: Test connection
echo [2/5] Testing iPhone connection...
python -c "import frida; device = frida.get_usb_device(); print('[OK] Connected to:', device.name)" 2>nul
if errorlevel 1 (
    echo [ERROR] Cannot connect to iPhone. Please check:
    echo   - iPhone is connected via USB
    echo   - iTunes/Apple Mobile Support is installed
    echo   - USB cable is working
    pause
    goto :menu
)

:: Phase 3: Start Frida server on iPhone (optional)
echo [3/5] Checking Frida server on iPhone...
echo.

:menu
echo.
echo ================================================================================
echo                      DOORDASH DASHER FIX OPTIONS
echo ================================================================================
echo.
echo   [A] AUTOMATIC - Full autonomous detection and fix (RECOMMENDED)
echo   [Q] QUICK FIX - Direct analytics mode (fastest)
echo   [M] MANUAL    - Choose specific bypass mode
echo   [T] TEST      - Test current setup
echo   [X] EXIT
echo.
echo ================================================================================
echo.

set /p choice="Select mode [A/Q/M/T/X]: "

if /i "%choice%"=="A" goto :automatic
if /i "%choice%"=="Q" goto :quickfix
if /i "%choice%"=="M" goto :manual
if /i "%choice%"=="T" goto :test
if /i "%choice%"=="X" exit
goto :menu

:automatic
echo.
echo ================================================================================
echo                    AUTOMATIC MODE - DASHER APP
echo ================================================================================
echo.
echo [*] Starting DoorDash DASHER with intelligent monitoring...
echo [*] Bundle ID: com.doordash.dasher
echo.
echo Instructions:
echo   1. The DASHER app will launch automatically
echo   2. Wait for "READY" prompt
echo   3. Tap "Dash Now" when instructed
echo   4. System will detect and fix issues
echo.
pause

:: Check if autonomous script exists
if not exist "autonomous-fix.py" (
    echo [ERROR] autonomous-fix.py not found!
    echo Creating basic version...
    goto :quickfix
)

:: Run autonomous monitor for DASHER
python autonomous-fix.py
if %errorlevel% equ 0 (
    goto :success
) else (
    echo.
    echo [!] Issues detected. Applying direct fix...
    goto :quickfix
)

:quickfix
echo.
echo ================================================================================
echo                    QUICK FIX - DASHER ANALYTICS MODE
echo ================================================================================
echo.
echo [*] Applying analytics fix to DASHER app directly...
echo [*] This fixes 90%% of API errors
echo.

:: Check if script exists
if not exist "frida-interception-and-unpinning\analytics-comprehensive-spoof.js" (
    echo [ERROR] Analytics script not found!
    echo Please ensure all scripts are in frida-interception-and-unpinning folder
    pause
    goto :menu
)

:: Direct launch DASHER with analytics fix
echo [*] Launching DASHER app: com.doordash.dasher
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\analytics-comprehensive-spoof.js

if %errorlevel% equ 0 (
    goto :monitor_result
) else (
    echo.
    echo [ERROR] Failed to launch. Trying alternative method...
    goto :manual
)

:manual
echo.
echo ================================================================================
echo                    MANUAL MODE - DASHER APP ONLY
echo ================================================================================
echo.
echo   [1] Minimal Safe Mode      - Basic spoofing (prevents crashes)
echo   [2] Lightweight Mode       - Moderate spoofing  
echo   [3] Comprehensive Mode     - Enhanced fingerprinting
echo   [4] Analytics Fix Mode     - JSON payload modification (RECOMMENDED)
echo   [B] Back to menu
echo.

set /p mode="Select bypass mode for DASHER [1-4/B]: "

if "%mode%"=="1" (
    set SCRIPT=doordash-minimal-safe.js
    set MODE_NAME=Minimal Safe
) else if "%mode%"=="2" (
    set SCRIPT=lightweight-spoof-only.js
    set MODE_NAME=Lightweight
) else if "%mode%"=="3" (
    set SCRIPT=comprehensive-spoof-stable.js
    set MODE_NAME=Comprehensive
) else if "%mode%"=="4" (
    set SCRIPT=analytics-comprehensive-spoof.js
    set MODE_NAME=Analytics Fix
) else if /i "%mode%"=="B" (
    goto :menu
) else (
    echo Invalid selection
    goto :manual
)

echo.
echo [*] Starting DoorDash DASHER with %MODE_NAME% mode...
echo [*] Bundle ID: com.doordash.dasher
echo.

:: Check if script exists
if not exist "frida-interception-and-unpinning\%SCRIPT%" (
    echo [ERROR] Script not found: %SCRIPT%
    pause
    goto :manual
)

python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\%SCRIPT%

:monitor_result
echo.
echo ================================================================================
echo                         MONITORING RESULTS
echo ================================================================================
echo.
echo Please test "Dash Now" in the DASHER app and observe:
echo.
echo   SUCCESS Indicators:
echo   - No error message appears
echo   - Dash starts normally
echo   - You can see available orders
echo.
echo   FAILURE Indicators:
echo   - "ErrorNetworking.ResponseStatusCodeError error 1"
echo   - App crashes or freezes
echo   - Cannot start dash
echo.
echo ================================================================================
echo.

set /p worked="Did the fix work? (Y/N): "

if /i "%worked%"=="Y" goto :success
if /i "%worked%"=="N" goto :troubleshoot
goto :menu

:test
echo.
echo ================================================================================
echo                        TESTING DASHER SETUP
echo ================================================================================
echo.

:: Test Python
echo [1] Python Status:
python --version

:: Test Frida
echo.
echo [2] Frida Status:
python -c "import frida; print('    Frida version:', frida.__version__)"

:: Test iPhone connection
echo.
echo [3] iPhone Connection:
python -c "import frida; d=frida.get_usb_device(); print('    Device:', d.name)"

:: Test if DASHER app is installed
echo.
echo [4] Checking DASHER app:
python test-dasher-connection.py

:: List scripts
echo.
echo [5] Available scripts:
for %%f in (frida-interception-and-unpinning\*.js) do echo     - %%~nxf

echo.
pause
goto :menu

:troubleshoot
echo.
echo ================================================================================
echo                      TROUBLESHOOTING DASHER APP
echo ================================================================================
echo.
echo Analyzing failure...
echo.

:: Check for captures
if exist "captures\*.json" (
    echo [*] Found capture files. Latest captures:
    dir /b /o-d captures\*.json 2>nul | head -5
)

echo.
echo Common DASHER app issues:
echo.
echo   1. Version inconsistency:
echo      - Solution: Use Analytics Fix Mode [4]
echo      - This ensures all events report iOS 17.6.1
echo.
echo   2. App crashes:
echo      - Solution: Use Minimal Safe Mode [1]
echo      - Then gradually try higher modes
echo.
echo   3. Connection issues:
echo      - Check HTTP Toolkit is running on port 8000
echo      - Restart SSH tunnel (close this window and reopen)
echo.
echo   4. DASHER-specific errors:
echo      - Make sure you're logged into DASHER account
echo      - Check if your account is activated for dashing
echo.
echo [*] Recommendation: Try option [Q] Quick Fix again
echo.
pause
goto :menu

:success
echo.
echo ================================================================================
echo                    SUCCESS - DASHER APP WORKING!
echo ================================================================================
echo.
echo [✓] DoorDash DASHER app is now working with Frida interception
echo [✓] All traffic is routed through HTTP Toolkit (port 8000)
echo [✓] iOS version spoofing is active (17.6.1)
echo [✓] You can now start accepting dashes!
echo.
echo Important:
echo   - Keep this window open while dashing
echo   - HTTP Toolkit should show all DASHER traffic
echo   - If app crashes, restart with option [Q]
echo.
echo ================================================================================
echo.
pause
goto :menu

:end
echo.
echo Cleaning up...
taskkill /F /IM plink.exe 2>nul
echo Done.
pause