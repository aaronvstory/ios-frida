@echo off
echo.
echo === Direct Attach: DoorDash with Enhanced Proxy ===
echo.

REM Check for DoorDash process
echo [1] Looking for DoorDash process...
python -c "import frida; device = frida.get_usb_device(); processes = device.enumerate_processes(); dd = [p for p in processes if 'Dash' in p.name or 'door' in p.name.lower()]; print(f'Found: {dd[0].name} (PID: {dd[0].pid})' if dd else 'Not found')" 2>nul

echo.
echo [2] Attaching with enhanced proxy script...
echo.

REM Direct attach with enhanced script
python -m frida_tools -U -p DasherApp -l frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy.js --no-pause

pause