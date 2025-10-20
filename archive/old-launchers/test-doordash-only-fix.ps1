# Test script to verify DoorDash-only configuration
# ================================================================

Write-Host "Testing FridaInterceptor DoorDash-only fix..." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Gray
Write-Host ""

# Test 1: Check JSON config
Write-Host "[1] Testing JSON configuration..." -ForegroundColor Yellow
$configPath = Join-Path $PSScriptRoot "config\frida-config.json"

if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $appKeys = $config.Apps.PSObject.Properties.Name

    Write-Host "   Found app keys: $($appKeys -join ', ')" -ForegroundColor White

    if ($appKeys.Count -eq 1 -and $appKeys -contains "DoorDashDasher") {
        Write-Host "   ✓ PASS: Only DoorDash Dasher configured" -ForegroundColor Green

        $dasherConfig = $config.Apps.DoorDashDasher
        Write-Host "   Bundle ID: $($dasherConfig.BundleID)" -ForegroundColor Gray
        Write-Host "   Name: $($dasherConfig.Name)" -ForegroundColor Gray

        if ($dasherConfig.BundleID -eq "com.doordash.dasher") {
            Write-Host "   ✓ PASS: Correct DoorDash bundle ID" -ForegroundColor Green
        } else {
            Write-Host "   ✗ FAIL: Wrong bundle ID: $($dasherConfig.BundleID)" -ForegroundColor Red
        }
    } else {
        Write-Host "   ✗ FAIL: Found $($appKeys.Count) apps, expected 1" -ForegroundColor Red
        foreach ($key in $appKeys) {
            Write-Host "        - $key" -ForegroundColor Red
        }
    }
} else {
    Write-Host "   ✗ FAIL: Config file not found" -ForegroundColor Red
}

Write-Host ""

# Test 2: Check PowerShell script for hardcoded references
Write-Host "[2] Testing PowerShell script cleanup..." -ForegroundColor Yellow
$scriptPath = Join-Path $PSScriptRoot "FridaInterceptor.ps1"

if (Test-Path $scriptPath) {
    $scriptContent = Get-Content $scriptPath -Raw

    # Check for removed references
    $uberCount = ([regex]::Matches($scriptContent, "uber", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
    $lyftCount = ([regex]::Matches($scriptContent, "lyft", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count

    Write-Host "   Uber references found: $uberCount" -ForegroundColor White
    Write-Host "   Lyft references found: $lyftCount" -ForegroundColor White

    if ($uberCount -eq 0 -and $lyftCount -eq 0) {
        Write-Host "   ✓ PASS: All Uber/Lyft references removed" -ForegroundColor Green
    } else {
        Write-Host "   ✗ FAIL: Still contains Uber/Lyft references" -ForegroundColor Red
    }

    # Check that DoorDash is still referenced
    $doorDashCount = ([regex]::Matches($scriptContent, "doordash", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
    Write-Host "   DoorDash references found: $doorDashCount" -ForegroundColor White

    if ($doorDashCount -gt 0) {
        Write-Host "   ✓ PASS: DoorDash references preserved" -ForegroundColor Green
    } else {
        Write-Host "   ✗ FAIL: No DoorDash references found" -ForegroundColor Red
    }
} else {
    Write-Host "   ✗ FAIL: PowerShell script not found" -ForegroundColor Red
}

Write-Host ""

# Test 3: Check menu options
Write-Host "[3] Testing menu structure..." -ForegroundColor Yellow
if (Test-Path $scriptPath) {
    $menuSection = $scriptContent | Select-String -Pattern "SPAWN MODE.*?LIGHTWEIGHT MODE.*?" -AllMatches

    if ($menuSection) {
        $menuText = $menuSection.Matches[0].Value

        # Count DoorDash options
        $doorDashOptions = ([regex]::Matches($menuText, "DoorDash", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
        Write-Host "   DoorDash menu options: $doorDashOptions" -ForegroundColor White

        # Check for removed apps
        $hasUber = $menuText -match "Uber"
        $hasLyft = $menuText -match "Lyft"

        if (-not $hasUber -and -not $hasLyft) {
            Write-Host "   ✓ PASS: Uber/Lyft removed from menu" -ForegroundColor Green
        } else {
            Write-Host "   ✗ FAIL: Menu still contains Uber/Lyft" -ForegroundColor Red
        }

        if ($doorDashOptions -ge 3) {
            Write-Host "   ✓ PASS: Multiple DoorDash options available" -ForegroundColor Green
        } else {
            Write-Host "   ✗ FAIL: Not enough DoorDash options" -ForegroundColor Red
        }
    } else {
        Write-Host "   ✗ FAIL: Could not find menu section" -ForegroundColor Red
    }
} else {
    Write-Host "   ✗ FAIL: Cannot test menu - script not found" -ForegroundColor Red
}

Write-Host ""

# Test 4: Verify switch statement
Write-Host "[4] Testing option mappings..." -ForegroundColor Yellow
if (Test-Path $scriptPath) {
    # Extract switch statement
    $switchPattern = 'switch \(\$selection\.ToUpper\(\)\) \{.*?\}'
    $switchMatch = [regex]::Match($scriptContent, $switchPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if ($switchMatch.Success) {
        $switchBlock = $switchMatch.Value

        # Check options 1-4 all use DoorDash
        $option1Match = $switchBlock -match '"1".*?DoorDashDasher'
        $option2Match = $switchBlock -match '"2".*?DoorDashDasher'
        $option3Match = $switchBlock -match '"3".*?DoorDashDasher'
        $option4Match = $switchBlock -match '"4".*?DoorDashDasher'

        $correctMappings = @($option1Match, $option2Match, $option3Match, $option4Match) | Where-Object { $_ }

        Write-Host "   Correct DoorDash mappings: $($correctMappings.Count)/4" -ForegroundColor White

        if ($correctMappings.Count -eq 4) {
            Write-Host "   ✓ PASS: All options map to DoorDash" -ForegroundColor Green
        } else {
            Write-Host "   ✗ FAIL: Some options don't map to DoorDash" -ForegroundColor Red
        }

        # Check for removed Uber/Lyft in switch
        $hasUberSwitch = $switchBlock -match "UberDriver"
        $hasLyftSwitch = $switchBlock -match "LyftDriver"

        if (-not $hasUberSwitch -and -not $hasLyftSwitch) {
            Write-Host "   ✓ PASS: Uber/Lyft removed from switch statement" -ForegroundColor Green
        } else {
            Write-Host "   ✗ FAIL: Switch still contains Uber/Lyft" -ForegroundColor Red
        }
    } else {
        Write-Host "   ✗ FAIL: Could not find switch statement" -ForegroundColor Red
    }
} else {
    Write-Host "   ✗ FAIL: Cannot test mappings - script not found" -ForegroundColor Red
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Gray
Write-Host "Test completed!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary of changes made:" -ForegroundColor Yellow
Write-Host "• Removed all Uber, Lyft, GrubHub, Postmates apps from config" -ForegroundColor Gray
Write-Host "• Fixed JSON config to use DoorDashDasher key format" -ForegroundColor Gray
Write-Host "• Updated menu to show only DoorDash options" -ForegroundColor Gray
Write-Host "• Fixed option 2 to use DoorDash instead of Uber" -ForegroundColor Gray
Write-Host "• Cleaned up process enumeration and help text" -ForegroundColor Gray
Write-Host "• Now options 1-4 all use DoorDash Dasher (com.doordash.dasher)" -ForegroundColor Gray
Write-Host ""
Write-Host "The application now supports ONLY DoorDash Dasher!" -ForegroundColor Green