@echo off
echo ========================================================================================
echo FridaInterceptor Ultimate - Initial Setup
echo ========================================================================================
echo.

echo Checking Python installation...
python --version 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found! Please install Python 3.8+ from https://www.python.org
    pause
    exit /b 1
)

echo.
echo Installing frida-tools with pip...
pip install frida-tools
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install frida-tools
    pause
    exit /b 1
)

echo.
echo Verifying installation...
frida --version
if %errorlevel% neq 0 (
    echo [WARNING] Frida installed but not in PATH
    echo You may need to add Python Scripts folder to your PATH
    echo Common locations:
    echo   - %LOCALAPPDATA%\Programs\Python\Python3XX\Scripts
    echo   - C:\Python3XX\Scripts
    echo   - %USERPROFILE%\AppData\Roaming\Python\Python3XX\Scripts
)

echo.
echo ========================================================================================
echo Setup Complete! You can now run start-ultimate.bat
echo ========================================================================================
pause