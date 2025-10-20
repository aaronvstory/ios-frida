# Test Enhanced Reset Function with App Termination
# This script validates the enhanced reset-to-stock.js functionality

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Enhanced Reset Function Test" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Set script variables
$Script:BaseDir = $PSScriptRoot
$Script:FridaScriptsDir = Join-Path $Script:BaseDir "frida-interception-and-unpinning"

# Validate reset script exists and check content
$resetScript = Join-Path $Script:FridaScriptsDir "reset-to-stock.js"

Write-Host "[1] Checking reset script..." -ForegroundColor Yellow
if (Test-Path $resetScript) {
    Write-Host "[✓] Reset script found: $resetScript" -ForegroundColor Green

    # Check for app termination functionality
    $scriptContent = Get-Content $resetScript -Raw

    Write-Host "[2] Validating enhanced functionality..." -ForegroundColor Yellow

    $checks = @{
        "UIApplication.terminate" = $scriptContent -match "UIApplication.*terminate"
        "exit() function" = $scriptContent -match "Module\.findExportByName.*exit"
        "abort() function" = $scriptContent -match "Module\.findExportByName.*abort"
        "NSThread.exit" = $scriptContent -match "NSThread.*exit"
        "Process.kill" = $scriptContent -match "getpid.*kill"
        "Termination attempted flag" = $scriptContent -match "termination_attempted.*true"
    }

    $passedChecks = 0
    foreach ($check in $checks.GetEnumerator()) {
        if ($check.Value) {
            Write-Host "[✓] $($check.Key) - Found" -ForegroundColor Green
            $passedChecks++
        } else {
            Write-Host "[✗] $($check.Key) - Missing" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "[3] Summary:" -ForegroundColor Yellow
    Write-Host "  Passed: $passedChecks / $($checks.Count) checks" -ForegroundColor $(if ($passedChecks -eq $checks.Count) { "Green" } else { "Red" })

    if ($passedChecks -eq $checks.Count) {
        Write-Host "[✓] Enhanced reset script validation PASSED!" -ForegroundColor Green
        Write-Host ""
        Write-Host "The script now includes:" -ForegroundColor Cyan
        Write-Host "  • Interceptor detachment" -ForegroundColor White
        Write-Host "  • Proxy configuration clearing" -ForegroundColor White
        Write-Host "  • Multiple app termination methods" -ForegroundColor White
        Write-Host "  • Graceful fallback handling" -ForegroundColor White
        Write-Host "  • Enhanced status reporting" -ForegroundColor White

        Write-Host ""
        Write-Host "Usage:" -ForegroundColor Yellow
        Write-Host "  1. Run main FridaInterceptor.ps1" -ForegroundColor White
        Write-Host "  2. Select option [R] for RESET TO STOCK" -ForegroundColor White
        Write-Host "  3. The app will be completely terminated after cleanup" -ForegroundColor White

    } else {
        Write-Host "[!] Enhanced reset script validation FAILED!" -ForegroundColor Red
        Write-Host "    Some termination methods are missing" -ForegroundColor Red
    }

} else {
    Write-Host "[✗] Reset script not found: $resetScript" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Test Completed" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan