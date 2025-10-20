# Verification script for FridaInterceptor installation
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  FridaInterceptor Installation Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$allGood = $true

# Check main files
Write-Host "`n[Checking Main Files]" -ForegroundColor Yellow
$mainFiles = @(
    @{Name="Main Launcher"; Path=".\start-frida-interceptor.bat"},
    @{Name="PowerShell Script"; Path=".\FridaInterceptor.ps1"},
    @{Name="Python Attach"; Path=".\frida-attach.py"},
    @{Name="Python Spawn"; Path=".\frida-spawn.py"}
)

foreach ($file in $mainFiles) {
    if (Test-Path $file.Path) {
        Write-Host "  ✓ $($file.Name)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($file.Name) - MISSING!" -ForegroundColor Red
        $allGood = $false
    }
}

# Check configuration
Write-Host "`n[Checking Configuration]" -ForegroundColor Yellow
$configFiles = @(
    @{Name="iOS Versions"; Path=".\config\ios-versions.json"},
    @{Name="Frida Config"; Path=".\config\frida-config.json"}
)

foreach ($file in $configFiles) {
    if (Test-Path $file.Path) {
        Write-Host "  ✓ $($file.Name)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($file.Name) - MISSING!" -ForegroundColor Red
        $allGood = $false
    }
}

# Check JavaScript templates
Write-Host "`n[Checking JavaScript Scripts]" -ForegroundColor Yellow
$jsFiles = @(
    @{Name="iOS Bypass Template"; Path=".\frida-interception-and-unpinning\ios-version-bypass-template.js"},
    @{Name="Enhanced SSL Bypass"; Path=".\frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js"}
)

foreach ($file in $jsFiles) {
    if (Test-Path $file.Path) {
        Write-Host "  ✓ $($file.Name)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($file.Name) - MISSING!" -ForegroundColor Red
        $allGood = $false
    }
}

# Check Python dependencies
Write-Host "`n[Checking Python & Frida]" -ForegroundColor Yellow
try {
    $fridaVersion = & python -c "import frida; print(f'v{frida.__version__}')" 2>$null
    if ($fridaVersion) {
        Write-Host "  ✓ Frida $fridaVersion installed" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Frida not installed" -ForegroundColor Red
        $allGood = $false
    }
} catch {
    Write-Host "  ✗ Python or Frida not available" -ForegroundColor Red
    $allGood = $false
}

# Check USB device connection
Write-Host "`n[Checking iPhone Connection]" -ForegroundColor Yellow
try {
    $deviceCheck = & python -c "import frida; d=frida.get_usb_device(); print(f'Connected: {d.name}')" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ $deviceCheck" -ForegroundColor Green
    } else {
        Write-Host "  ✗ No iPhone detected via USB" -ForegroundColor Yellow
        Write-Host "    (Connect iPhone to test full functionality)" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "  ✗ Cannot check device connection" -ForegroundColor Yellow
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
if ($allGood) {
    Write-Host "  ✅ READY TO USE!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Launch with: .\start-frida-interceptor.bat" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Quick iOS Bypass for DoorDash:" -ForegroundColor Cyan
    Write-Host "  1. Run launcher" -ForegroundColor White
    Write-Host "  2. Press [V] to select iOS version" -ForegroundColor White
    Write-Host "  3. Choose iOS 17.6.1" -ForegroundColor White
    Write-Host "  4. Press [4] to attach to DasherApp" -ForegroundColor White
} else {
    Write-Host "  ⚠️ INSTALLATION INCOMPLETE" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Please fix missing components above" -ForegroundColor Yellow
}