# Test the Ctrl+C handler functionality

Write-Host "Testing Ctrl+C Handler Implementation" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Yellow
Write-Host ""

# Source the main script to get functions
. .\FridaInterceptor.ps1

Write-Host "[+] Functions loaded successfully" -ForegroundColor Green
Write-Host ""

# Test the Start-ProcessWithCtrlC function exists
if (Get-Command Start-ProcessWithCtrlC -ErrorAction SilentlyContinue) {
    Write-Host "[✓] Start-ProcessWithCtrlC function found" -ForegroundColor Green
} else {
    Write-Host "[!] Start-ProcessWithCtrlC function NOT found" -ForegroundColor Red
}

# Check if all spawn/attach functions have been updated
Write-Host ""
Write-Host "Checking function updates:" -ForegroundColor Cyan

$functionsToCheck = @(
    "Start-SpawnMode",
    "Start-AttachMode",
    "Start-LightweightMode"
)

foreach ($funcName in $functionsToCheck) {
    $funcDef = (Get-Command $funcName).Definition
    if ($funcDef -match "Start-ProcessWithCtrlC") {
        Write-Host "[✓] $funcName uses new Ctrl+C handler" -ForegroundColor Green
    } else {
        Write-Host "[!] $funcName NOT updated" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Testing a simple process with Ctrl+C handler:" -ForegroundColor Yellow
Write-Host ""

# Create a test Python script that runs indefinitely
$testScript = @'
import time
print("[+] Test script started - running indefinitely")
print("[+] Press Ctrl+C in PowerShell to test handler")
while True:
    time.sleep(1)
    print(".", end="", flush=True)
'@

$testScriptPath = "test-ctrl-c-script.py"
Set-Content -Path $testScriptPath -Value $testScript

Write-Host "Starting test process..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to test the handler" -ForegroundColor Yellow
Write-Host ""

# Test the handler
$exitCode = Start-ProcessWithCtrlC -FilePath "python" -ArgumentList $testScriptPath

if ($exitCode -eq $null) {
    Write-Host "[✓] Ctrl+C handler worked! Process stopped gracefully" -ForegroundColor Green
} else {
    Write-Host "[!] Process exited with code: $exitCode" -ForegroundColor Yellow
}

# Clean up
Remove-Item $testScriptPath -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "======================================" -ForegroundColor Yellow
Write-Host "Test Complete!" -ForegroundColor Green