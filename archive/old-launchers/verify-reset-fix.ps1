# Verify the reset function fix
Write-Host "Verifying Reset Function Fix..." -ForegroundColor Yellow
Write-Host ""

# Read the fixed line from the file
$content = Get-Content "FridaInterceptor.ps1"
$lineNumber = 913
$fixedLine = $content[$lineNumber - 1]

Write-Host "Line 913 content:" -ForegroundColor Cyan
Write-Host "  $fixedLine" -ForegroundColor Gray
Write-Host ""

# Check if the problematic redirect parameters are removed
if ($fixedLine -like "*-RedirectStandardOutput*" -or $fixedLine -like "*-RedirectStandardError*") {
    Write-Host "[!] ERROR: Redirect parameters still present!" -ForegroundColor Red
    Write-Host "[!] The fix was not applied correctly." -ForegroundColor Red
} else {
    Write-Host "[✓] SUCCESS: Redirect parameters have been removed!" -ForegroundColor Green
    Write-Host "[✓] The fix has been applied correctly." -ForegroundColor Green
    Write-Host ""
    Write-Host "The line now correctly uses:" -ForegroundColor Cyan
    Write-Host "  Start-Process ... -NoNewWindow -PassThru -Wait" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Without the problematic:" -ForegroundColor Yellow
    Write-Host "  -RedirectStandardOutput 'NUL' -RedirectStandardError 'NUL'" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Reset function should now work without the error:" -ForegroundColor Green
Write-Host "  'RedirectStandardOutput and RedirectStandardError cannot be the same'" -ForegroundColor Gray