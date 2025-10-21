# FridaDasher Launcher - Complete with ALL options for DASHER app only
# Target: com.doordash.dasher (NOT consumer app)

param(
    [string]$Mode = ""
)

$ErrorActionPreference = "Continue"
Clear-Host

# Configuration
$Script:DasherBundleID = "com.doordash.dasher"  # DASHER app only!
$Script:BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:ScriptsDir = Join-Path $BaseDir "frida-interception-and-unpinning"

function Show-Banner {
    Write-Host "=================================================================================" -ForegroundColor Cyan
    Write-Host "                     DOORDASH DASHER INTERCEPTOR v2.0                          " -ForegroundColor Yellow
    Write-Host "=================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Target: DoorDash DASHER App (com.doordash.dasher)" -ForegroundColor Green
    Write-Host "  Purpose: Fix 'ErrorNetworking.ResponseStatusCodeError error 1'" -ForegroundColor Green
    Write-Host ""
}

function Test-Connection {
    Write-Host "Testing connection..." -ForegroundColor Cyan
    $result = python -c "import frida; d=frida.get_usb_device(); print(d.name)" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[✓] Connected to: $result" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[✗] Connection failed" -ForegroundColor Red
        return $false
    }
}

function Show-Menu {
    Clear-Host
    Show-Banner
    
    Write-Host "  SPAWN MODE (App Restarts):" -ForegroundColor Yellow
    Write-Host "  [1] Basic DoorDash mode        - Standard bypass"
    Write-Host "  [2] Enhanced DoorDash mode      - With proxy routing"
    Write-Host "  [3] Minimal Safe mode           - Prevents crashes"
    Write-Host ""
    
    Write-Host "  ATTACH MODE (Stay Logged In):" -ForegroundColor Cyan
    Write-Host "  [4] Attach to running DASHER   - Keep session"
    Write-Host ""
    
    Write-Host "  LIGHTWEIGHT MODE:" -ForegroundColor Magenta
    Write-Host "  [5] Lightweight spoofing        - Fast performance"
    Write-Host ""
    
    Write-Host "  COMPREHENSIVE MODE:" -ForegroundColor Yellow
    Write-Host "  [6] Comprehensive (spawn)       - Full fingerprinting"
    Write-Host "  [7] Comprehensive (attach)      - Full fingerprinting + session"
    Write-Host ""
    
    Write-Host "  ANALYTICS FIX MODE (Recommended):" -ForegroundColor Green
    Write-Host "  [8] Analytics Fix (spawn)       - Fixes version inconsistency" -ForegroundColor Green
    Write-Host "  [9] Analytics Fix (attach)      - Fixes + keeps session" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "  UTILITIES:" -ForegroundColor White
    Write-Host "  [T] Test connection"
    Write-Host "  [L] List running apps"
    Write-Host "  [S] Start SSH tunnel"
    Write-Host "  [Q] Quick Analytics Fix (one-click)"
    Write-Host "  [X] Exit"
    Write-Host ""
    Write-Host "=================================================================================" -ForegroundColor DarkGray
}

function Start-DasherWithScript {
    param(
        [string]$ScriptName,
        [string]$ModeName,
        [string]$Method = "spawn"
    )
    
    $scriptPath = Join-Path $Script:ScriptsDir $ScriptName
    
    if (-not (Test-Path $scriptPath)) {
        Write-Host "[!] Script not found: $ScriptName" -ForegroundColor Red
        Write-Host "Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host ""
    Write-Host "Starting DASHER in $ModeName mode..." -ForegroundColor Yellow
    Write-Host "Bundle ID: $Script:DasherBundleID" -ForegroundColor Gray
    Write-Host "Script: $ScriptName" -ForegroundColor Gray
    Write-Host ""
    
    if ($Method -eq "attach") {
        # Find running DASHER process
        Write-Host "Looking for running DASHER app..." -ForegroundColor Cyan
        $pythonCmd = @"
import frida
device = frida.get_usb_device()
processes = device.enumerate_processes()
dasher = [p for p in processes if 'dasher' in p.name.lower() or 'com.doordash.dasher' in str(p)]
if dasher:
    print(dasher[0].pid)
"@
        $pid = python -c $pythonCmd 2>$null
        
        if ($pid) {
            Write-Host "[✓] Found DASHER with PID: $pid" -ForegroundColor Green
            Write-Host "Attaching..." -ForegroundColor Yellow
            
            $cmd = "python `"$(Join-Path $Script:BaseDir 'frida-attach.py')`" $pid `"$scriptPath`""
            Invoke-Expression $cmd
        } else {
            Write-Host "[!] DASHER not running. Please open the app first." -ForegroundColor Red
        }
    } else {
        # Spawn mode
        Write-Host "DASHER will restart..." -ForegroundColor Yellow
        $cmd = "python `"$(Join-Path $Script:BaseDir 'frida-spawn.py')`" `"$Script:DasherBundleID`" `"$scriptPath`""
        Invoke-Expression $cmd
    }
    
    Write-Host ""
    Write-Host "Press any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Start-QuickFix {
    Clear-Host
    Show-Banner
    Write-Host "QUICK ANALYTICS FIX - One-Click Solution" -ForegroundColor Green
    Write-Host ""
    Write-Host "This will apply the analytics fix that resolves 90% of API errors" -ForegroundColor Yellow
    Write-Host ""
    
    Start-DasherWithScript -ScriptName "analytics-comprehensive-spoof.js" -ModeName "Analytics Fix" -Method "spawn"
}

function List-RunningApps {
    Write-Host "Scanning for apps..." -ForegroundColor Cyan
    python -c @"
import frida
device = frida.get_usb_device()
apps = device.enumerate_applications()
dasher_apps = [app for app in apps if 'dasher' in app.identifier.lower() or 'doordash' in app.identifier.lower()]
print('\nDoorDash Apps:')
for app in dasher_apps:
    print(f'  - {app.identifier}: {app.name}')
processes = device.enumerate_processes()
dasher_procs = [p for p in processes if 'dasher' in p.name.lower() or 'doordash' in p.name.lower()]
print('\nRunning DoorDash Processes:')
for proc in dasher_procs:
    print(f'  - {proc.name} (PID: {proc.pid})')
"@
    Write-Host ""
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Start-SSHTunnel {
    Write-Host "Starting SSH tunnel..." -ForegroundColor Yellow
    Start-Process -FilePath "plink" -ArgumentList "-L 27042:127.0.0.1:22 root@192.168.50.113 -pw alpine" -WindowStyle Minimized
    Start-Sleep -Seconds 2
    Write-Host "[✓] SSH tunnel started" -ForegroundColor Green
    Start-Sleep -Seconds 1
}

# Main execution
if (-not (Test-Connection)) {
    Write-Host ""
    Write-Host "Please ensure:" -ForegroundColor Yellow
    Write-Host "  1. iPhone is connected via USB"
    Write-Host "  2. Frida server is running on iPhone"
    Write-Host "  3. iTunes/Apple Mobile Support is installed"
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

# Main loop
while ($true) {
    Show-Menu
    $choice = Read-Host "Select option"
    
    switch ($choice) {
        "1" { Start-DasherWithScript -ScriptName "universal-ssl-pinning-bypass-with-proxy.js" -ModeName "Basic" }
        "2" { Start-DasherWithScript -ScriptName "enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js" -ModeName "Enhanced" }
        "3" { Start-DasherWithScript -ScriptName "doordash-minimal-safe.js" -ModeName "Minimal Safe" }
        "4" { Start-DasherWithScript -ScriptName "attach-mode-proxy.js" -ModeName "Attach" -Method "attach" }
        "5" { Start-DasherWithScript -ScriptName "lightweight-spoof-only.js" -ModeName "Lightweight" }
        "6" { Start-DasherWithScript -ScriptName "comprehensive-spoof-stable.js" -ModeName "Comprehensive Spawn" }
        "7" { Start-DasherWithScript -ScriptName "comprehensive-spoof-attach.js" -ModeName "Comprehensive Attach" -Method "attach" }
        "8" { Start-DasherWithScript -ScriptName "analytics-comprehensive-spoof.js" -ModeName "Analytics Fix Spawn" }
        "9" { Start-DasherWithScript -ScriptName "analytics-comprehensive-spoof.js" -ModeName "Analytics Fix Attach" -Method "attach" }
        "T" { Test-Connection; Write-Host "Press any key..."; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        "L" { List-RunningApps }
        "S" { Start-SSHTunnel }
        "Q" { Start-QuickFix }
        "X" { exit }
        default { Write-Host "Invalid selection" -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}