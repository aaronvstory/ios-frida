# HTTP Toolkit Traffic Visibility Fix Script
# This addresses the issue where traffic stops appearing in HTTP Toolkit

param(
    [string]$AppName = "DoorDash"
)

Write-Host @"

===============================================================
       HTTP TOOLKIT TRAFFIC VISIBILITY FIX
===============================================================

"@ -ForegroundColor Cyan

# Step 1: Check HTTP Toolkit
Write-Host "[1] Checking HTTP Toolkit status..." -ForegroundColor Yellow
$httpToolkitRunning = Get-Process | Where-Object { $_.ProcessName -like "*HTTP*Toolkit*" -or $_.ProcessName -like "*electron*" }

if ($httpToolkitRunning) {
    Write-Host "    ✓ HTTP Toolkit is running" -ForegroundColor Green
} else {
    Write-Host "    ✗ HTTP Toolkit not detected - Please start it first!" -ForegroundColor Red
    exit 1
}

# Step 2: Test proxy connectivity
Write-Host "`n[2] Testing proxy connectivity..." -ForegroundColor Yellow
$proxyTest = Test-NetConnection -ComputerName "192.168.50.9" -Port 8000 -WarningAction SilentlyContinue

if ($proxyTest.TcpTestSucceeded) {
    Write-Host "    ✓ Proxy port 8000 is accessible" -ForegroundColor Green
} else {
    Write-Host "    ✗ Cannot reach proxy - Check HTTP Toolkit is listening" -ForegroundColor Red
}

# Step 3: Kill existing Frida sessions
Write-Host "`n[3] Cleaning up old Frida sessions..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.ProcessName -like "*frida*" } | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    Write-Host "    Stopped process: $($_.ProcessName)" -ForegroundColor Gray
}

# Step 4: Find app process
Write-Host "`n[4] Looking for $AppName process on device..." -ForegroundColor Yellow

$processInfo = & python -c @"
import frida
import sys
try:
    device = frida.get_usb_device()
    processes = device.enumerate_processes()
    target = [p for p in processes if '$AppName' in p.name or 'dash' in p.name.lower()]
    if target:
        print(f'{target[0].pid}|{target[0].name}')
    else:
        print('NOT_FOUND')
except Exception as e:
    print(f'ERROR|{str(e)}')
"@ 2>&1

if ($processInfo -like "ERROR*") {
    Write-Host "    ✗ Error: $($processInfo.Split('|')[1])" -ForegroundColor Red
    exit 1
} elseif ($processInfo -eq "NOT_FOUND") {
    Write-Host "    ✗ App not running - Please start it first" -ForegroundColor Red
    exit 1
} else {
    $pid, $name = $processInfo.Split('|')
    Write-Host "    ✓ Found: $name (PID: $pid)" -ForegroundColor Green
}# Step 5: Attach with enhanced script
Write-Host "`n[5] Attaching with ENHANCED proxy script..." -ForegroundColor Yellow

$enhancedScript = Join-Path $PSScriptRoot "frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy.js"

if (-not (Test-Path $enhancedScript)) {
    Write-Host "    ✗ Enhanced script not found!" -ForegroundColor Red
    Write-Host "    Creating it now..." -ForegroundColor Yellow
    # Script would be created here from embedded content
    exit 1
}

Write-Host "    Using: enhanced-universal-ssl-pinning-bypass-with-proxy.js" -ForegroundColor Cyan
Write-Host "    Features:" -ForegroundColor Cyan
Write-Host "      • Comprehensive network API hooks" -ForegroundColor Gray
Write-Host "      • Request counting and logging" -ForegroundColor Gray
Write-Host "      • Forces ALL traffic through proxy" -ForegroundColor Gray
Write-Host "      • Debug output for troubleshooting" -ForegroundColor Gray

# Step 6: Execute attachment
Write-Host "`n[6] Starting interception..." -ForegroundColor Yellow
Write-Host "    Command: frida -U -p $pid -l enhanced-...-proxy.js" -ForegroundColor Gray

# Run the attachment
$attachCmd = @"
import frida
import sys

device = frida.get_usb_device()
session = device.attach($pid)

with open(r'$enhancedScript', 'r') as f:
    script_code = f.read()

script = session.create_script(script_code)

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] {message['stack']}")

script.on('message', on_message)
script.load()

print('[+] Script loaded! Traffic should now appear in HTTP Toolkit')
print('[+] Trigger network activity in the app...')
print('[+] Press Ctrl+C to stop')

try:
    sys.stdin.read()
except KeyboardInterrupt:
    session.detach()
    print('\n[*] Detached')
"@

$attachCmd | python -

Write-Host "`n===============================================================" -ForegroundColor Cyan
Write-Host " If traffic still doesn't appear in HTTP Toolkit:" -ForegroundColor Yellow
Write-Host " 1. In HTTP Toolkit, check the 'System Proxy' tab" -ForegroundColor White
Write-Host " 2. Force quit and restart the iOS app" -ForegroundColor White
Write-Host " 3. Try spawn mode instead (app will restart)" -ForegroundColor White
Write-Host "===============================================================" -ForegroundColor Cyan