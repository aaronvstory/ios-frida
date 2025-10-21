# Simple validation of reset-to-stock.js script content
# This validates the script without running the full interface

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Reset Script Content Validation" -ForegroundColor White
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$resetScript = Join-Path $PSScriptRoot "frida-interception-and-unpinning\reset-to-stock.js"

if (Test-Path $resetScript) {
    Write-Host "[✓] Reset script found" -ForegroundColor Green

    $content = Get-Content $resetScript -Raw
    $lineCount = (Get-Content $resetScript).Count

    Write-Host "[✓] Script size: $lineCount lines" -ForegroundColor Green

    # Check core functionality
    $features = @{
        "Interceptor.detachAll()" = $content -match "Interceptor\.detachAll"
        "Proxy clearing" = $content -match "setConnectionProxyDictionary_\(null\)"
        "App termination" = $content -match "terminate.*app.*complete.*reset"
        "Multiple termination methods" = ($content -match "UIApplication" -and $content -match "exit\(" -and $content -match "abort\(" -and $content -match "NSThread" -and $content -match "kill")
        "Error handling" = $content -match "catch\(e\)"
        "Status reporting" = $content -match "termination_attempted.*true"
    }

    Write-Host ""
    Write-Host "Feature validation:" -ForegroundColor Yellow
    foreach ($feature in $features.GetEnumerator()) {
        $status = if ($feature.Value) { "[✓]" } else { "[✗]" }
        $color = if ($feature.Value) { "Green" } else { "Red" }
        Write-Host "  $status $($feature.Key)" -ForegroundColor $color
    }

    $passedFeatures = ($features.Values | Where-Object { $_ -eq $true }).Count
    $totalFeatures = $features.Count

    Write-Host ""
    if ($passedFeatures -eq $totalFeatures) {
        Write-Host "[✓] All features validated successfully!" -ForegroundColor Green
        Write-Host "[✓] Enhanced reset script is ready for use" -ForegroundColor Green
    } else {
        Write-Host "[!] Feature validation incomplete: $passedFeatures/$totalFeatures" -ForegroundColor Yellow
    }

} else {
    Write-Host "[✗] Reset script not found: $resetScript" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Validation Complete" -ForegroundColor White
Write-Host "==========================================" -ForegroundColor Cyan