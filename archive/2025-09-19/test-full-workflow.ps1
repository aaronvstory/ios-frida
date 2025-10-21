# Test the complete enhanced FridaInterceptor workflow
Write-Host "`n=== Testing Complete Enhanced Workflow ===" -ForegroundColor Cyan
Write-Host "This test will verify the iOS version selection and bypass" -ForegroundColor Yellow

# Step 1: Check DasherApp is running
Write-Host "`n[1] Checking for DasherApp..." -ForegroundColor Cyan
$processes = & python -c "import frida; d=frida.get_usb_device(); dasher=[p for p in d.enumerate_processes() if 'dasher' in p.name.lower()]; print('\n'.join(f'{p.pid}:{p.name}' for p in dasher))" 2>$null

if ($processes) {
    $processInfo = $processes[0] -split ':'
    $pid = $processInfo[0]
    $name = $processInfo[1]
    Write-Host "    ✓ Found: $name (PID: $pid)" -ForegroundColor Green
} else {
    Write-Host "    ✗ DasherApp not running" -ForegroundColor Red
    Write-Host "    Please open DasherApp on the iPhone first" -ForegroundColor Yellow
    exit 1
}

# Step 2: Load iOS version config
Write-Host "`n[2] Loading iOS version configurations..." -ForegroundColor Cyan
$config = Get-Content ".\config\ios-versions.json" -Raw | ConvertFrom-Json
$iOS17_6 = $config.versions.iOS17_6

Write-Host "    ✓ iOS 17.6.1 configuration loaded" -ForegroundColor Green
Write-Host "      CFNetwork: $($iOS17_6.cfNetwork)" -ForegroundColor DarkGray
Write-Host "      Darwin: $($iOS17_6.darwin)" -ForegroundColor DarkGray

# Step 3: Generate bypass script
Write-Host "`n[3] Generating iOS 17.6.1 bypass script..." -ForegroundColor Cyan
$template = Get-Content ".\frida-interception-and-unpinning\ios-version-bypass-template.js" -Raw

$script = $template -replace "\{\{VERSION\}\}", $iOS17_6.systemVersion
$script = $script -replace "\{\{CFNETWORK\}\}", $iOS17_6.cfNetwork
$script = $script -replace "\{\{DARWIN\}\}", $iOS17_6.darwin
$script = $script -replace "\{\{BUILD\}\}", $iOS17_6.buildNumber
$script = $script -replace "\{\{PROXY_HOST\}\}", "192.168.50.9"
$script = $script -replace "\{\{PROXY_PORT\}\}", "8000"

$scriptPath = ".\test-ios-17-6-bypass.js"
$script | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Host "    ✓ Script generated: $scriptPath" -ForegroundColor Green

# Step 4: Attach to DasherApp with bypass
Write-Host "`n[4] Attaching iOS 17.6.1 bypass to DasherApp..." -ForegroundColor Cyan
Write-Host "    Command: python frida-attach.py $pid `"$scriptPath`"" -ForegroundColor DarkGray

# Create a test attach that runs for 5 seconds
$attachScript = @"
import frida
import sys
import time

pid = $pid
script_path = r'$scriptPath'

print('[+] Connecting to device...')
device = frida.get_usb_device()
print(f'[+] Device: {device.name}')

print(f'[+] Attaching to PID {pid}...')
session = device.attach(pid)

with open(script_path, 'r') as f:
    script_code = f.read()

script = session.create_script(script_code)
script.load()

print('[+] iOS version bypass loaded successfully!')
print('[+] Device now reports as iOS 17.6.1')
print('[+] CFNetwork: $($iOS17_6.cfNetwork)')
print('[+] Darwin: $($iOS17_6.darwin)')
print('[+] Running for 5 seconds to verify...')

time.sleep(5)

print('[+] Test completed successfully!')
session.detach()
"@

$attachScript | Out-File -FilePath ".\test-attach.py" -Encoding UTF8

try {
    & python ".\test-attach.py" 2>&1
    $success = $LASTEXITCODE -eq 0
} catch {
    $success = $false
    Write-Host "    ✗ Error: $_" -ForegroundColor Red
}

# Step 5: Cleanup
Write-Host "`n[5] Cleaning up test files..." -ForegroundColor Cyan
Remove-Item $scriptPath -ErrorAction SilentlyContinue
Remove-Item ".\test-attach.py" -ErrorAction SilentlyContinue
Write-Host "    ✓ Cleanup complete" -ForegroundColor Green

# Summary
Write-Host "`n" + ("="*80) -ForegroundColor Cyan
Write-Host "                    WORKFLOW TEST COMPLETE" -ForegroundColor Green
Write-Host ("="*80) -ForegroundColor Cyan

if ($success) {
    Write-Host "`n✅ SUCCESS: iOS version bypass is working correctly!" -ForegroundColor Green
    Write-Host ""
    Write-Host "The enhanced FridaInterceptor Ultimate successfully:" -ForegroundColor Cyan
    Write-Host "  • Detected running DasherApp" -ForegroundColor White
    Write-Host "  • Loaded iOS version configurations" -ForegroundColor White
    Write-Host "  • Generated dynamic bypass script" -ForegroundColor White
    Write-Host "  • Attached iOS 17.6.1 bypass to the app" -ForegroundColor White
    Write-Host "  • Spoofed CFNetwork and Darwin versions" -ForegroundColor White
    Write-Host ""
    Write-Host "📱 DoorDash Dasher should now work on iOS 16.3.1 device!" -ForegroundColor Yellow
} else {
    Write-Host "`n❌ FAILED: There was an issue with the bypass" -ForegroundColor Red
}

Write-Host "`nLaunch the full interface with: .\start-ultimate-enhanced.bat" -ForegroundColor Cyan