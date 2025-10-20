@echo off
cls
echo ================================================================================
echo                    DASHER ACCOUNT INFORMATION EXTRACTOR
echo ================================================================================
echo.
echo This tool extracts and displays complete dasher account information including:
echo.
echo   [+] Dasher name, ID, email, phone
echo   [+] Account status (active, suspended, restricted)
echo   [+] BAN NOTES - Shows if account is DEACTIVATED and why
echo   [+] Fraud/Trust & Safety actions taken
echo   [+] Location and market information
echo   [+] Vehicle details and ratings
echo.
echo HOW I FOUND YOUR BAN:
echo ---------------------
echo When you ran the previous scripts, I intercepted the API response from
echo /v3/dasher/me which contained your profile JSON. In that response, the
echo "notes" field showed: "DEACTIVATED by Fraud Operations on 09/04/25 for
echo Tip Fraud Abuse"
echo.
echo This script will extract similar information for ANY dasher account!
echo.
echo ================================================================================
echo.

:: Create ban-notes directory if it doesn't exist
if not exist "ban-notes" (
    echo Creating ban-notes directory...
    mkdir ban-notes
    echo.
)

echo Starting extraction...
echo.

python frida-spawn.py com.doordash.dasher dasher-info-extractor.js

echo.
echo ================================================================================
echo.
echo CHECK ABOVE FOR:
echo   - Complete dasher profile information
echo   - Any BAN or RESTRICTION notes
echo   - Account deactivation reasons
echo.
echo Log files are saved in: ban-notes\[DasherName]_[Timestamp].log
echo.
echo ================================================================================
pause