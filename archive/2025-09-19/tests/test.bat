@echo off
REM FridaInterceptor Ultimate Test Suite Launcher
REM Quick launcher for the PowerShell test script

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                      FRIDA INTERCEPTOR TEST LAUNCHER                        ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

REM Check if PowerShell script exists
if not exist "test-frida-interceptor.ps1" (
    echo [ERROR] Test script not found: test-frida-interceptor.ps1
    echo Make sure you're running this from the correct directory.
    pause
    exit /b 1
)

REM Parse command line arguments for common options
set ARGS=
if "%1"=="-quick" set ARGS=-Quick
if "%1"=="-verbose" set ARGS=-Verbose  
if "%1"=="-help" goto :help
if "%1"=="/?" goto :help

echo Running FridaInterceptor test suite...
echo.

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "test-frida-interceptor.ps1" %ARGS% %*

echo.
echo Test completed. Check results above.
pause
exit /b %ERRORLEVEL%

:help
echo.
echo FridaInterceptor Ultimate Test Suite
echo.
echo Usage: test.bat [options]
echo.
echo Options:
echo   -quick      Skip interactive tests (faster)
echo   -verbose    Show detailed output
echo   -help       Show this help message
echo.
echo Examples:
echo   test.bat                    # Full test suite
echo   test.bat -quick            # Quick validation only  
echo   test.bat -verbose          # Detailed output
echo.
pause
exit /b 0