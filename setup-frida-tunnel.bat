@echo off
echo Creating SSH tunnel for Frida (via 3uTools tunnel)...
echo.
echo This will forward iPhone's frida-server port 27042 to local 127.0.0.1:27042
echo.

REM Use plink to create tunnel through 3uTools existing SSH connection
REM 3uTools has already opened 127.0.0.1:22 -> iPhone:22
REM We just need to forward the frida port

echo Starting tunnel...
plink.exe -ssh -L 27042:127.0.0.1:27042 mobile@127.0.0.1 -P 22 -pw alpine -N

echo.
echo Tunnel closed.
pause
