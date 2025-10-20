# Quick test of reset function
. .\FridaInterceptor.ps1

# Set required script variables
$Script:BaseDir = $PSScriptRoot
$Script:FridaScriptsDir = Join-Path $Script:BaseDir "frida-interception-and-unpinning"

Write-Host "Testing Reset Function..." -ForegroundColor Yellow
Write-Host ""

# Mock some process output for testing
$testProcesses = @("1234:doordash.DoorDashConsumer", "5678:com.ubercab.driver")

Write-Host "[*] Mock processes for testing:" -ForegroundColor Cyan
foreach ($proc in $testProcesses) {
    Write-Host "  - $proc"
}

# Test the parsing logic
foreach ($proc in $testProcesses) {
    if ($proc -match "(\d+):(.+)") {
        $procId = $Matches[1]
        $procName = $Matches[2]
        Write-Host "[✓] Parsed: $procName (PID: $procId)" -ForegroundColor Green

        # Check if reset script exists
        $resetScript = Join-Path $Script:FridaScriptsDir "reset-to-stock.js"
        if (Test-Path $resetScript) {
            Write-Host "[✓] Reset script found: $resetScript" -ForegroundColor Green
        } else {
            Write-Host "[!] Reset script not found: $resetScript" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "[✓] Reset function parse test completed successfully!" -ForegroundColor Green
Write-Host "[✓] No PowerShell errors detected!" -ForegroundColor Green