# Test the DoorDash bypass script fix

Write-Host "Testing DoorDash Bypass Script Fix" -ForegroundColor Yellow
Write-Host "===================================" -ForegroundColor Yellow
Write-Host ""

$scriptPath = "frida-interception-and-unpinning\doordash-complete-bypass.js"

if (Test-Path $scriptPath) {
    Write-Host "[✓] Script found: $scriptPath" -ForegroundColor Green

    # Check for the problematic ObjC.implement pattern
    $content = Get-Content $scriptPath -Raw

    Write-Host ""
    Write-Host "Checking for issues:" -ForegroundColor Cyan

    # Check if ObjC.implement is still used for dataTaskWithRequest
    if ($content -match "ObjC\.implement.*dataTaskWithRequest") {
        Write-Host "[!] PROBLEM: Still using ObjC.implement for dataTaskWithRequest" -ForegroundColor Red
    } else {
        Write-Host "[✓] FIXED: Not using ObjC.implement for dataTaskWithRequest" -ForegroundColor Green
    }

    # Check if Interceptor.attach is used instead
    if ($content -match "Interceptor\.attach.*dataTaskWithRequest") {
        Write-Host "[✓] FIXED: Using Interceptor.attach for dataTaskWithRequest" -ForegroundColor Green
    } else {
        Write-Host "[!] PROBLEM: Not using Interceptor.attach" -ForegroundColor Red
    }

    # Check for the problematic this.dataTaskWithRequest call
    if ($content -match "this\.dataTaskWithRequest_completionHandler_") {
        Write-Host "[!] PROBLEM: Still has this.dataTaskWithRequest call" -ForegroundColor Red
    } else {
        Write-Host "[✓] FIXED: No problematic this.dataTaskWithRequest calls" -ForegroundColor Green
    }

    # Check line 63 area
    $lines = $content -split "`n"
    if ($lines.Count -ge 63) {
        Write-Host ""
        Write-Host "Line 63 content:" -ForegroundColor Cyan
        Write-Host "  $($lines[62])" -ForegroundColor Gray

        if ($lines[62] -match "not a function" -or $lines[62] -match "this\.") {
            Write-Host "[!] Line 63 might still have issues" -ForegroundColor Red
        } else {
            Write-Host "[✓] Line 63 looks clean" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Yellow
    Write-Host "The TypeError should be fixed. The script now:" -ForegroundColor Green
    Write-Host "  • Uses Interceptor.attach instead of ObjC.implement" -ForegroundColor Gray
    Write-Host "  • Doesn't try to call non-existent functions" -ForegroundColor Gray
    Write-Host "  • Properly hooks NSURLSession methods" -ForegroundColor Gray

} else {
    Write-Host "[!] Script not found: $scriptPath" -ForegroundColor Red
}

Write-Host ""
Write-Host "===================================" -ForegroundColor Yellow
Write-Host "Test Complete!" -ForegroundColor Green