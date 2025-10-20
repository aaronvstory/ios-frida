# FridaInterceptor Ultimate Test Suite
# Comprehensive validation of all Frida iOS interception functionality

param(
    [switch]$Quick,          # Skip interactive tests
    [switch]$Verbose,        # Show detailed output
    [string]$Device = "",    # Specific device ID
    [switch]$NoColor         # Disable colored output
)

# Enable UTF-8 output and colors
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
if (-not $NoColor) {
    $Host.UI.RawUI.BackgroundColor = "Black"
    $Host.UI.RawUI.ForegroundColor = "White"
}

# Color functions
function Write-Success($msg) { if (-not $NoColor) { Write-Host $msg -ForegroundColor Green } else { Write-Host "[OK] $msg" } }
function Write-Error($msg) { if (-not $NoColor) { Write-Host $msg -ForegroundColor Red } else { Write-Host "[ERROR] $msg" } }
function Write-Warning($msg) { if (-not $NoColor) { Write-Host $msg -ForegroundColor Yellow } else { Write-Host "[WARN] $msg" } }
function Write-Info($msg) { if (-not $NoColor) { Write-Host $msg -ForegroundColor Cyan } else { Write-Host "[INFO] $msg" } }
function Write-Header($msg) { if (-not $NoColor) { Write-Host $msg -ForegroundColor Magenta } else { Write-Host "=== $msg ===" } }

# Test tracking
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsSkipped = 0

function Test-Result {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = "",
        [bool]$Critical = $false
    )
    
    if ($Passed) {
        Write-Success "✓ $TestName"
        if ($Details -and $Verbose) { Write-Info "  $Details" }
        $script:TestsPassed++
    } else {
        Write-Error "✗ $TestName"
        if ($Details) { Write-Warning "  $Details" }
        $script:TestsFailed++
        
        if ($Critical) {
            Write-Error "CRITICAL FAILURE: Cannot continue testing"
            Show-Results
            exit 1
        }
    }
}

function Test-Skip {
    param([string]$TestName, [string]$Reason)
    Write-Warning "⚠ $TestName (SKIPPED: $Reason)"
    $script:TestsSkipped++
}

function Show-Results {
    Write-Host ""
    Write-Header "TEST RESULTS SUMMARY"
    Write-Host "─────────────────────────────────────────────" -ForegroundColor Gray
    Write-Success "Passed:  $script:TestsPassed"
    Write-Error "Failed:  $script:TestsFailed" 
    Write-Warning "Skipped: $script:TestsSkipped"
    Write-Host "Total:   $($script:TestsPassed + $script:TestsFailed + $script:TestsSkipped)"
    
    $successRate = if (($script:TestsPassed + $script:TestsFailed) -gt 0) {
        [math]::Round(($script:TestsPassed / ($script:TestsPassed + $script:TestsFailed)) * 100, 1)
    } else { 0 }
    
    Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 90) { "Green" } elseif ($successRate -ge 75) { "Yellow" } else { "Red" })
}

# Banner
Clear-Host
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                      FRIDA INTERCEPTOR ULTIMATE                             ║" -ForegroundColor Cyan  
Write-Host "║                        Comprehensive Test Suite                             ║" -ForegroundColor Cyan
Write-Host "║                                                                              ║" -ForegroundColor Cyan
Write-Host "║  Tests: SSH tunnel, Frida tools, app configs, proxy script, helpers        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$startTime = Get-Date
Write-Info "Test started at: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""

# Test 1: Basic File Structure
Write-Header "1. FILE STRUCTURE VALIDATION"

$requiredFiles = @(
    "frida-interceptor-ultimate.js",
    "frida_ios_proxy.py", 
    "setup_proxy.py",
    "config.json"
)

$baseDir = "C:\claude\ios frida"
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $baseDir $file
    Test-Result "Required file exists: $file" (Test-Path $filePath) -Critical $true
}# Test 2: Configuration Validation
Write-Header "2. CONFIGURATION VALIDATION"

$configPath = Join-Path $baseDir "config.json"
try {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    Test-Result "Config file is valid JSON" $true
    
    # Check required config fields
    $requiredFields = @("device_ip", "device_port", "frida_server_port", "proxy_port", "apps")
    foreach ($field in $requiredFields) {
        $hasField = $config.PSObject.Properties.Name -contains $field
        Test-Result "Config has '$field' field" $hasField
    }
    
    # Validate apps configuration
    if ($config.apps) {
        $appCount = ($config.apps | Get-Member -MemberType NoteProperty).Count
        Test-Result "Apps configuration exists" ($appCount -gt 0) "Found $appCount app configurations"
        
        foreach ($appProperty in $config.apps.PSObject.Properties) {
            $appName = $appProperty.Name
            $appConfig = $appProperty.Value
            
            $hasIdentifier = $appConfig.PSObject.Properties.Name -contains "identifier"
            $hasMode = $appConfig.PSObject.Properties.Name -contains "mode"
            
            Test-Result "App '$appName' has identifier" $hasIdentifier
            Test-Result "App '$appName' has mode" $hasMode
            
            if ($hasMode) {
                $validMode = $appConfig.mode -in @("spawn", "attach")
                Test-Result "App '$appName' mode is valid" $validMode "Mode: $($appConfig.mode)"
            }
        }
    }
} catch {
    Test-Result "Config file parsing" $false $_.Exception.Message -Critical $true
}

# Test 3: Script Content Validation  
Write-Header "3. SCRIPT CONTENT VALIDATION"

$jsScriptPath = Join-Path $baseDir "frida-interceptor-ultimate.js"
if (Test-Path $jsScriptPath) {
    $jsContent = Get-Content $jsScriptPath -Raw
    
    # Check for key functionality
    $checks = @{
        "HTTP/HTTPS interception" = $jsContent -match "URLSession|NSURLConnection"
        "Certificate pinning bypass" = $jsContent -match "SecTrustEvaluate|pinning"
        "Method hooking framework" = $jsContent -match "Interceptor\.attach"
        "Proxy configuration" = $jsContent -match "CFNetworkProxies|proxy"
        "Error handling" = $jsContent -match "try\s*\{|catch"
        "Logging functionality" = $jsContent -match "console\.log|send\("
    }
    
    foreach ($check in $checks.GetEnumerator()) {
        Test-Result $check.Key $check.Value
    }
}

# Test 4: Python Helper Scripts
Write-Header "4. PYTHON HELPER SCRIPTS VALIDATION"

$pythonScripts = @("frida_ios_proxy.py", "setup_proxy.py")
foreach ($script in $pythonScripts) {
    $scriptPath = Join-Path $baseDir $script
    if (Test-Path $scriptPath) {
        $content = Get-Content $scriptPath -Raw
        
        # Basic syntax check by attempting to parse
        try {
            # Use python to check syntax
            $result = & python -m py_compile $scriptPath 2>&1
            $syntaxOk = $LASTEXITCODE -eq 0
            Test-Result "Python script '$script' syntax" $syntaxOk
        } catch {
            Test-Result "Python script '$script' syntax" $false "Python not available for syntax check"
        }
        
        # Check for required imports based on script purpose
        if ($script -eq "frida_ios_proxy.py") {
            Test-Result "$script has frida import" ($content -match "import frida")
            Test-Result "$script has proxy functionality" ($content -match "proxy|intercept")
        } elseif ($script -eq "setup_proxy.py") {
            Test-Result "$script has configuration setup" ($content -match "config|setup")
        }
    }
}

# Test 5: SSH and Device Connectivity
Write-Header "5. SSH AND DEVICE CONNECTIVITY"

if (-not $Quick) {
    Write-Info "Testing SSH tunnel connectivity..."
    
    # Try to establish SSH connection (non-interactive test)
    $sshTest = $false
    try {
        if ($config.device_ip -and $config.device_port) {
            # Test basic network connectivity first
            $ping = Test-NetConnection -ComputerName $config.device_ip -Port $config.device_port -InformationLevel Quiet -WarningAction SilentlyContinue
            Test-Result "Device network connectivity" $ping "Testing $($config.device_ip):$($config.device_port)"
            
            if ($ping) {
                Write-Info "Attempting SSH connection test (5 second timeout)..."
                $sshCmd = "ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -p $($config.device_port) root@$($config.device_ip) 'echo SSH_TEST_OK'"
                $sshResult = Invoke-Expression $sshCmd 2>$null
                $sshTest = $sshResult -match "SSH_TEST_OK"
            }
        }
    } catch {
        # SSH test is optional
    }
    
    if ($sshTest) {
        Test-Result "SSH connectivity" $true
    } else {
        Test-Skip "SSH connectivity" "Cannot establish connection or device not available"
    }
} else {
    Test-Skip "SSH connectivity" "Quick mode enabled"
}# Test 6: Frida Tools Availability
Write-Header "6. FRIDA TOOLS AVAILABILITY"

# Test frida-ps command
Write-Info "Testing frida-ps command availability..."
try {
    $fridaPsResult = & frida-ps --version 2>&1
    $fridaAvailable = $LASTEXITCODE -eq 0 -and $fridaPsResult -match "\d+\.\d+\.\d+"
    Test-Result "frida-ps command available" $fridaAvailable "Version: $fridaPsResult"
} catch {
    Test-Result "frida-ps command available" $false "Command not found in PATH"
}

# Test frida command  
try {
    $fridaResult = & frida --version 2>&1
    $fridaCoreAvailable = $LASTEXITCODE -eq 0 -and $fridaResult -match "\d+\.\d+\.\d+"
    Test-Result "frida core command available" $fridaCoreAvailable "Version: $fridaResult"
} catch {
    Test-Result "frida core command available" $false "Command not found in PATH"
}

# Test device connectivity with frida-ps
if (-not $Quick -and $fridaAvailable) {
    Write-Info "Testing device connectivity with frida-ps..."
    try {
        $deviceArg = if ($Device) { "-D $Device" } else { "" }
        $psResult = Invoke-Expression "frida-ps -U $deviceArg" 2>&1
        $deviceConnected = $LASTEXITCODE -eq 0 -and $psResult -notmatch "Failed to.*device"
        Test-Result "Frida device connectivity" $deviceConnected
        
        if ($deviceConnected -and $Verbose) {
            Write-Info "Available processes:"
            $psResult | Select-Object -First 5 | ForEach-Object { Write-Info "  $_" }
        }
    } catch {
        Test-Result "Frida device connectivity" $false $_.Exception.Message
    }
} else {
    Test-Skip "Frida device connectivity" $(if ($Quick) { "Quick mode enabled" } else { "frida-ps not available" })
}

# Test 7: App Configuration Testing
Write-Header "7. APP CONFIGURATION TESTING"

if ($config.apps) {
    foreach ($appProperty in $config.apps.PSObject.Properties) {
        $appName = $appProperty.Name
        $appConfig = $appProperty.Value
        
        Write-Info "Testing configuration for: $appName"
        
        # Test identifier format
        if ($appConfig.identifier) {
            $validIdentifier = $appConfig.identifier -match "^[a-zA-Z0-9\.\-_]+$"
            Test-Result "$appName identifier format" $validIdentifier "Identifier: $($appConfig.identifier)"
        }
        
        # Test mode validity
        if ($appConfig.mode) {
            $validMode = $appConfig.mode -in @("spawn", "attach")
            Test-Result "$appName mode validity" $validMode "Mode: $($appConfig.mode)"
        }
        
        # Test optional script path
        if ($appConfig.script) {
            $scriptExists = Test-Path $appConfig.script
            Test-Result "$appName custom script exists" $scriptExists "Script: $($appConfig.script)"
        }
        
        # If not in quick mode and frida is available, test app availability on device
        if (-not $Quick -and $fridaAvailable -and $appConfig.identifier) {
            try {
                $deviceArg = if ($Device) { "-D $Device" } else { "" }
                $appCheck = Invoke-Expression "frida-ps -U $deviceArg -a" 2>&1 | Where-Object { $_ -match $appConfig.identifier }
                $appFound = $appCheck -ne $null
                Test-Result "$appName found on device" $appFound
            } catch {
                Test-Skip "$appName device check" "Could not query device"
            }
        }
    }
}

# Test 8: Proxy Script Functionality
Write-Header "8. PROXY SCRIPT FUNCTIONALITY"

$proxyScriptPath = Join-Path $baseDir "frida_ios_proxy.py"
if (Test-Path $proxyScriptPath) {
    # Test script can be imported
    try {
        $testScript = @"
import sys
sys.path.insert(0, r'$baseDir')
try:
    import frida_ios_proxy
    print('IMPORT_SUCCESS')
except ImportError as e:
    print(f'IMPORT_ERROR: {e}')
"@
        $tempScript = [System.IO.Path]::GetTempFileName() + ".py"
        Set-Content $tempScript $testScript
        
        $importResult = & python $tempScript 2>&1
        $canImport = $importResult -match "IMPORT_SUCCESS"
        Test-Result "Proxy script can be imported" $canImport
        
        Remove-Item $tempScript -ErrorAction SilentlyContinue
    } catch {
        Test-Result "Proxy script import test" $false "Python not available"
    }
}

# Test 9: Integration Test (if not in quick mode)
Write-Header "9. INTEGRATION TEST"

if (-not $Quick) {
    Write-Info "Running integration test..."
    
    # Create a simple test script that attempts to load the main script
    $testIntegration = @"
import json
import os

# Test config loading
config_path = r'$baseDir\config.json'
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
    print('CONFIG_LOAD_SUCCESS')
except Exception as e:
    print(f'CONFIG_LOAD_ERROR: {e}')

# Test script file access
script_path = r'$baseDir\frida-interceptor-ultimate.js'
try:
    with open(script_path, 'r') as f:
        content = f.read()
        if len(content) > 1000:  # Reasonable size check
            print('SCRIPT_LOAD_SUCCESS')
        else:
            print('SCRIPT_LOAD_ERROR: Script too small')
except Exception as e:
    print(f'SCRIPT_LOAD_ERROR: {e}')
"@
    
    try {
        $tempIntegrationScript = [System.IO.Path]::GetTempFileName() + ".py"
        Set-Content $tempIntegrationScript $testIntegration
        
        $integrationResult = & python $tempIntegrationScript 2>&1
        
        $configLoadOk = $integrationResult -match "CONFIG_LOAD_SUCCESS"
        $scriptLoadOk = $integrationResult -match "SCRIPT_LOAD_SUCCESS"
        
        Test-Result "Config loading integration" $configLoadOk
        Test-Result "Script loading integration" $scriptLoadOk
        
        Remove-Item $tempIntegrationScript -ErrorAction SilentlyContinue
    } catch {
        Test-Result "Integration test" $false "Python not available for integration test"
    }
} else {
    Test-Skip "Integration test" "Quick mode enabled"
}# Test 10: Smoke Test - Full Workflow Simulation
Write-Header "10. SMOKE TEST - FULL WORKFLOW SIMULATION"

if (-not $Quick) {
    Write-Info "Simulating full workflow..."
    
    # Test 1: Configuration parsing and validation
    try {
        $smokeConfig = Get-Content $configPath -Raw | ConvertFrom-Json
        $configParseOk = $true
        Test-Result "Smoke test: Config parsing" $configParseOk
    } catch {
        Test-Result "Smoke test: Config parsing" $false
        $configParseOk = $false
    }
    
    # Test 2: Script file accessibility
    $scriptAccessible = Test-Path $jsScriptPath
    Test-Result "Smoke test: Script file access" $scriptAccessible
    
    # Test 3: Python helper script syntax
    $pythonHelpersOk = $true
    foreach ($script in $pythonScripts) {
        $scriptPath = Join-Path $baseDir $script
        if (-not (Test-Path $scriptPath)) {
            $pythonHelpersOk = $false
            break
        }
    }
    Test-Result "Smoke test: Python helpers available" $pythonHelpersOk
    
    # Test 4: Basic frida command availability
    try {
        $null = & frida --version 2>&1
        $fridaSmokeOk = $LASTEXITCODE -eq 0
    } catch {
        $fridaSmokeOk = $false
    }
    Test-Result "Smoke test: Frida command available" $fridaSmokeOk
    
    # Overall smoke test result
    $smokeTestPassed = $configParseOk -and $scriptAccessible -and $pythonHelpersOk -and $fridaSmokeOk
    Test-Result "SMOKE TEST OVERALL" $smokeTestPassed $(if ($smokeTestPassed) { "All components ready" } else { "Some components failed" })
    
} else {
    Test-Skip "Smoke test" "Quick mode enabled"
}

# Test 11: Security and Permissions Check
Write-Header "11. SECURITY AND PERMISSIONS CHECK"

# Check if running as administrator (recommended for iOS device access)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Test-Result "Running as Administrator" $isAdmin "Recommended for iOS device access"

# Check for potentially dangerous configurations
if ($config) {
    # Check for default/weak passwords in config
    $configJson = $config | ConvertTo-Json -Depth 10
    $hasWeakCredentials = $configJson -match '"password"\s*:\s*"(root|admin|password|123456)"'
    Test-Result "No weak credentials in config" (-not $hasWeakCredentials) "Check for default passwords"
    
    # Check for localhost bindings (security consideration)
    $hasLocalhostBinding = $configJson -match '"(127\.0\.0\.1|localhost)"'
    if ($hasLocalhostBinding) {
        Write-Warning "  Note: Found localhost bindings - ensure this is intentional for security"
    }
}

# Test 12: Environment and Dependencies
Write-Header "12. ENVIRONMENT AND DEPENDENCIES"

# Check Python availability and version
try {
    $pythonVersion = & python --version 2>&1
    $pythonOk = $LASTEXITCODE -eq 0 -and $pythonVersion -match "Python \d+\.\d+"
    Test-Result "Python available" $pythonOk "Version: $pythonVersion"
} catch {
    Test-Result "Python available" $false "Python not found in PATH"
}

# Check for required Python packages
$requiredPackages = @("frida", "frida-tools")
foreach ($package in $requiredPackages) {
    try {
        $packageCheck = & python -c "import $package; print('$package OK')" 2>&1
        $packageOk = $packageCheck -match "$package OK"
        Test-Result "Python package: $package" $packageOk
    } catch {
        Test-Result "Python package: $package" $false "Import failed"
    }
}

# Check USB debugging tools availability
$usbTools = @("iproxy", "idevice_id", "ideviceinfo")
foreach ($tool in $usbTools) {
    try {
        $null = Get-Command $tool -ErrorAction Stop
        Test-Result "USB tool: $tool" $true
    } catch {
        Test-Skip "USB tool: $tool" "Not in PATH (may not be required)"
    }
}

# Final Results and Recommendations
Write-Host ""
Write-Header "TEST COMPLETION"

$endTime = Get-Date
$duration = $endTime - $startTime
Write-Info "Test completed at: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Info "Total duration: $($duration.ToString('mm\:ss'))"

Show-Results

# Provide recommendations based on test results
Write-Host ""
Write-Header "RECOMMENDATIONS"

if ($script:TestsFailed -eq 0) {
    Write-Success "🎉 All tests passed! Your FridaInterceptor setup is ready to use."
} else {
    Write-Warning "⚠️  Some tests failed. Review the following:"
    
    if (-not $isAdmin) {
        Write-Info "• Consider running as Administrator for better device access"
    }
    
    if (-not $fridaAvailable) {
        Write-Info "• Install Frida tools: pip install frida-tools"
    }
    
    if (-not $Quick -and $script:TestsSkipped -gt 0) {
        Write-Info "• Run without -Quick flag for complete device connectivity tests"
    }
    
    Write-Info "• Check configuration file for any missing or invalid settings"
    Write-Info "• Ensure iOS device is connected and accessible"
}

Write-Host ""
Write-Info "To run specific test categories:"
Write-Info "• Quick validation: .\test-frida-interceptor.ps1 -Quick"
Write-Info "• Verbose output: .\test-frida-interceptor.ps1 -Verbose" 
Write-Info "• Specific device: .\test-frida-interceptor.ps1 -Device 'your-device-id'"
Write-Info "• No colors: .\test-frida-interceptor.ps1 -NoColor"

Write-Host ""
Write-Host "Script location: $PSCommandPath"
Write-Success "FridaInterceptor Ultimate Test Suite completed!"

# Exit with appropriate code
exit $(if ($script:TestsFailed -eq 0) { 0 } else { 1 })