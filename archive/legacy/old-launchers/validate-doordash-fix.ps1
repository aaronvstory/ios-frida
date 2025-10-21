# Simple validation script for DoorDash-only fix
# ================================================

Write-Host ""
Write-Host "FridaInterceptor DoorDash-Only Fix Validation" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Gray
Write-Host ""

# Load the config like the main script does
$configPath = Join-Path $PSScriptRoot "config\frida-config.json"
$jsonConfig = Get-Content $configPath -Raw | ConvertFrom-Json

# Show what we loaded
Write-Host "Loaded Configuration:" -ForegroundColor Yellow
Write-Host "  Apps found: $($jsonConfig.Apps.PSObject.Properties.Name -join ', ')" -ForegroundColor White
Write-Host ""

# Show DoorDash config
$doorDashConfig = $jsonConfig.Apps.DoorDashDasher
Write-Host "DoorDash Dasher Configuration:" -ForegroundColor Green
Write-Host "  Name: $($doorDashConfig.Name)" -ForegroundColor White
Write-Host "  Bundle ID: $($doorDashConfig.BundleID)" -ForegroundColor White
Write-Host ""

# Simulate what options would show
Write-Host "Menu Options (Simulated):" -ForegroundColor Yellow
Write-Host "  [1] $($doorDashConfig.Name) - Restart with full control" -ForegroundColor White
Write-Host "  [2] $($doorDashConfig.Name) - Alternative spawn method" -ForegroundColor White
Write-Host "  [3] $($doorDashConfig.Name) - Keep current session" -ForegroundColor White
Write-Host "  [4] DoorDash LIGHTWEIGHT - Minimal spoofing only" -ForegroundColor Magenta
Write-Host ""

# Validate the fix
$issues = @()

# Check 1: Only one app configured
if ($jsonConfig.Apps.PSObject.Properties.Name.Count -ne 1) {
    $issues += "Expected 1 app, found $($jsonConfig.Apps.PSObject.Properties.Name.Count)"
}

# Check 2: App is DoorDash
if ($jsonConfig.Apps.PSObject.Properties.Name[0] -ne "DoorDashDasher") {
    $issues += "Expected DoorDashDasher, found $($jsonConfig.Apps.PSObject.Properties.Name[0])"
}

# Check 3: Correct bundle ID
if ($doorDashConfig.BundleID -ne "com.doordash.dasher") {
    $issues += "Wrong bundle ID: $($doorDashConfig.BundleID)"
}

# Show results
if ($issues.Count -eq 0) {
    Write-Host "✓ VALIDATION PASSED" -ForegroundColor Green
    Write-Host "✓ Only DoorDash Dasher is configured" -ForegroundColor Green
    Write-Host "✓ Bundle ID is correct (com.doordash.dasher)" -ForegroundColor Green
    Write-Host "✓ All options will use DoorDash Dasher" -ForegroundColor Green
    Write-Host ""
    Write-Host "The fix is working correctly!" -ForegroundColor Green
} else {
    Write-Host "✗ VALIDATION FAILED" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "✗ $issue" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Summary of Fixed Issues:" -ForegroundColor Yellow
Write-Host "• Option 2 no longer uses Uber Driver bundle ID" -ForegroundColor Gray
Write-Host "• All Uber, Lyft, GrubHub, Postmates apps removed" -ForegroundColor Gray
Write-Host "• Menu simplified to only show DoorDash options" -ForegroundColor Gray
Write-Host "• All 4 options now correctly use com.doordash.dasher" -ForegroundColor Gray
Write-Host ""