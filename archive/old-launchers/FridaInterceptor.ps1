# FridaInterceptor Ultimate v5.0 - Enhanced with iOS Version Bypass (FINAL FIX)
# Complete integration with multiple iOS version spoofing options
# ============================================================================

param(
    [string]$App = "",
    [string]$Mode = "",
    [string]$iOSVersion = "",
    [switch]$Debug,
    [switch]$Help
)

# Set console encoding
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

# Script configuration
$Script:Version = "5.0 Enhanced"
$Script:BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:LogDir = Join-Path $BaseDir "logs"
$Script:FridaScriptsDir = Join-Path $BaseDir "frida-interception-and-unpinning"
$Script:ConfigDir = Join-Path $BaseDir "config"
$Script:SelectedIOSVersion = $null
$Script:GeneratedScriptPath = $null

# Load iOS version configuration
function Load-iOSVersionConfig {
    $configPath = Join-Path $Script:ConfigDir "ios-versions.json"
    if (Test-Path $configPath) {
        $Script:iOSVersions = Get-Content $configPath -Raw | ConvertFrom-Json
    } else {
        Write-Host "[!] iOS versions config not found, using defaults" -ForegroundColor Yellow
        # Fallback configuration
        $Script:iOSVersions = @{
            versions = @{
                iOS17 = @{
                    displayName = "iOS 17.5.1 (Stable)"
                    systemVersion = "17.5.1"
                    cfNetwork = "1485.0.5"
                    darwin = "23.5.0"
                    buildNumber = "21F79"
                    description = "Most compatible version"
                }
            }
            defaultVersion = "iOS17"
        }
    }
}

# Initialize and check dependencies
function Initialize-Dependencies {
    Write-Host "Checking dependencies..." -ForegroundColor Cyan

    # Check for Python
    $pythonPath = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonPath) {
        $pythonPath = Get-Command python3 -ErrorAction SilentlyContinue
    }

    if (-not $pythonPath) {
        Write-Host "[!] Python not found. Please install Python 3.8+ first." -ForegroundColor Red
        Write-Host "    Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
        exit 1
    }

    # Check for frida
    $pythonTest = & python -c "import frida; print(frida.__version__)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Frida not installed. Installing..." -ForegroundColor Yellow
        & pip install frida-tools
    }

    $Script:UsePythonFrida = $true
}

# Load configuration - FIXED to handle both JSON and default config properly
function Load-Configuration {
    $configPath = Join-Path $Script:ConfigDir "frida-config.json"

    if (Test-Path $configPath) {
        try {
            $jsonConfig = Get-Content $configPath -Raw | ConvertFrom-Json

            # FIXED: Convert PSCustomObject to nested hashtables
            $Script:Config = @{
                Network = @{
                    WindowsIP = if ($jsonConfig.Network.WindowsIP) { $jsonConfig.Network.WindowsIP } else { "192.168.50.9" }
                    ProxyPort = if ($jsonConfig.Network.ProxyPort) { $jsonConfig.Network.ProxyPort } else { 8000 }
                    iPhoneIP = if ($jsonConfig.Network.iPhoneIP) { $jsonConfig.Network.iPhoneIP } else { "192.168.50.113" }
                    SSHPort = if ($jsonConfig.Network.SSHPort) { $jsonConfig.Network.SSHPort } else { 27042 }
                }
                Apps = @{
                    DoorDashDasher = @{
                        BundleID = if ($jsonConfig.Apps.DoorDashDasher.BundleID) { $jsonConfig.Apps.DoorDashDasher.BundleID } else { "com.doordash.dasher" }
                        Name = if ($jsonConfig.Apps.DoorDashDasher.Name) { $jsonConfig.Apps.DoorDashDasher.Name } else { "DoorDash Dasher" }
                    }
                }
            }
            Write-Host "[✓] Configuration loaded successfully" -ForegroundColor Green
        } catch {
            Write-Host "[!] Error loading configuration: $_" -ForegroundColor Red
            Initialize-DefaultConfig
        }
    } else {
        Write-Host "[!] Config file not found, using defaults" -ForegroundColor Yellow
        Initialize-DefaultConfig
    }
}

# Initialize default configuration - Now using hashtables
function Initialize-DefaultConfig {
    $Script:Config = @{
        Network = @{
            WindowsIP = "192.168.50.9"
            ProxyPort = 8000
            iPhoneIP = "192.168.50.113"
            SSHPort = 27042
        }
        Apps = @{
            DoorDashDasher = @{
                BundleID = "com.doordash.dasher"
                Name = "DoorDash Dasher"
            }
        }
    }
}

# Color output helper
function Write-ColorOutput {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "INFO" { if ($Script:Debug) { Write-Host $logMessage -ForegroundColor Cyan } }
        default { if ($Script:Debug) { Write-Host $logMessage } }
    }
}

# Display banner
function Show-Banner {
    Clear-Host
    Write-ColorOutput @"

       ███████╗██████╗ ██╗██████╗  █████╗     ██╗   ██╗███████╗
       ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗    ██║   ██║██╔════╝
       █████╗  ██████╔╝██║██║  ██║███████║    ██║   ██║███████╗
       ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║    ╚██╗ ██╔╝╚════██║
       ██║     ██║  ██║██║██████╔╝██║  ██║     ╚████╔╝ ███████║
       ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝      ╚═══╝  ╚══════╝

     Ultimate Interceptor v$($Script:Version) - iOS Version Bypass Edition
"@ "Cyan"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
}

# Show iOS version selection menu - FIXED to properly save selection
function Show-IOSVersionMenu {
    Clear-Host
    Show-Banner

    Write-ColorOutput "  iOS VERSION BYPASS SELECTION" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    Write-ColorOutput "  This feature spoofs your iOS version to bypass app restrictions" "Cyan"
    Write-ColorOutput "  DoorDash blocks iOS 16 and below - use iOS 17+ to fix" "Yellow"
    Write-Host ""

    $versionKeys = @()
    $index = 1

    foreach ($key in $Script:iOSVersions.versions.PSObject.Properties.Name) {
        if ($key -ne "custom") {
            $version = $Script:iOSVersions.versions.$key
            $versionKeys += $key

            # Highlight recommended version
            if ($key -eq "iOS17_6") {
                Write-Host ("  [{0}] {1}" -f $index, $version.displayName) -ForegroundColor Green
                Write-Host ("       iOS {0} | CFNetwork {1} | Darwin {2}" -f $version.systemVersion, $version.cfNetwork, $version.darwin) -ForegroundColor DarkGreen
                Write-Host ("       {0} [RECOMMENDED FOR DOORDASH]" -f $version.description) -ForegroundColor Green
            } else {
                Write-Host ("  [{0}] {1}" -f $index, $version.displayName)
                Write-Host ("       iOS {0} | CFNetwork {1} | Darwin {2}" -f $version.systemVersion, $version.cfNetwork, $version.darwin) -ForegroundColor DarkGray
                Write-Host ("       {0}" -f $version.description) -ForegroundColor DarkGray
            }
            Write-Host ""
            $index++
        }
    }

    Write-Host "  [0] No Bypass - Use original iOS version (may fail on DoorDash)" -ForegroundColor DarkYellow
    Write-Host "  [B] Back to main menu" -ForegroundColor Cyan
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    $selection = Read-Host "Select iOS version to spoof"

    if ($selection -eq "0") {
        $Script:SelectedIOSVersion = $null
        Write-Host "[i] No iOS bypass selected - using original version" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        # Return to main menu after selection
        Show-AppMenu
        return
    }
    elseif ($selection -eq "B" -or $selection -eq "b") {
        Show-AppMenu
        return
    }
    elseif ($selection -match '^\d+$') {
        $idx = [int]$selection - 1
        if ($idx -ge 0 -and $idx -lt $versionKeys.Count) {
            $selectedKey = $versionKeys[$idx]
            $versionData = $Script:iOSVersions.versions.$selectedKey

            # FIXED: Convert PSCustomObject to Hashtable
            $Script:SelectedIOSVersion = @{
                displayName = $versionData.displayName
                systemVersion = $versionData.systemVersion
                cfNetwork = $versionData.cfNetwork
                darwin = $versionData.darwin
                buildNumber = $versionData.buildNumber
                description = $versionData.description
            }

            Write-Host "[✓] Selected: $($Script:SelectedIOSVersion.displayName)" -ForegroundColor Green
            Write-Host "[i] Your device will appear as iOS $($Script:SelectedIOSVersion.systemVersion)" -ForegroundColor Cyan
            Start-Sleep -Seconds 2
            # Return to main menu after selection
            Show-AppMenu
            return
        }
    }

    Write-Host "[!] Invalid selection" -ForegroundColor Red
    Start-Sleep -Seconds 1
    Show-IOSVersionMenu
}

# Generate dynamic bypass script with selected iOS version
function Generate-DynamicBypassScript {
    param([hashtable]$AppInfo)

    if (-not $Script:SelectedIOSVersion) {
        return $null
    }

    # Read the base template
    $templatePath = Join-Path $Script:FridaScriptsDir "ios-bypass-with-ssl.js"
    if (-not (Test-Path $templatePath)) {
        Write-Host "[!] Template script not found: $templatePath" -ForegroundColor Red
        return $null
    }

    $scriptContent = Get-Content $templatePath -Raw

    # Replace hardcoded values with selected version
    $scriptContent = $scriptContent -replace 'var spoofVersion = "17.6.1";', "var spoofVersion = `"$($Script:SelectedIOSVersion.systemVersion)`";"
    $scriptContent = $scriptContent -replace 'var spoofBuild = "21G93";', "var spoofBuild = `"$($Script:SelectedIOSVersion.buildNumber)`";"
    $scriptContent = $scriptContent -replace 'var spoofDarwin = "23.6.0";', "var spoofDarwin = `"$($Script:SelectedIOSVersion.darwin)`";"
    $scriptContent = $scriptContent -replace 'var spoofCFNetwork = "1490.0.4";', "var spoofCFNetwork = `"$($Script:SelectedIOSVersion.cfNetwork)`";"

    # Update proxy settings
    $scriptContent = $scriptContent -replace 'var proxyHost = "192.168.50.9";', "var proxyHost = `"$($Script:Config.Network.WindowsIP)`";"
    $scriptContent = $scriptContent -replace 'var proxyPort = 8000;', "var proxyPort = $($Script:Config.Network.ProxyPort);"

    # Save to temporary file
    $outputPath = Join-Path $Script:FridaScriptsDir "generated-dynamic-ios-bypass.js"
    $scriptContent | Out-File -FilePath $outputPath -Encoding UTF8 -Force

    Write-Log "Generated dynamic bypass script for iOS $($Script:SelectedIOSVersion.systemVersion)" "SUCCESS"
    return $outputPath
}

# Generate bypass script from template - Now works with Hashtable
function Generate-BypassScript {
    param($VersionInfo)

    if (-not $VersionInfo) {
        return $null
    }

    $templatePath = Join-Path $Script:FridaScriptsDir "ios-version-bypass-template.js"
    if (-not (Test-Path $templatePath)) {
        Write-Log "Template not found: $templatePath" "ERROR"
        return $null
    }

    $template = Get-Content $templatePath -Raw

    # Replace placeholders
    $script = $template -replace "\{\{VERSION\}\}", $VersionInfo.systemVersion
    $script = $script -replace "\{\{CFNETWORK\}\}", $VersionInfo.cfNetwork
    $script = $script -replace "\{\{DARWIN\}\}", $VersionInfo.darwin
    $script = $script -replace "\{\{BUILD\}\}", $VersionInfo.buildNumber
    $script = $script -replace "\{\{PROXY_HOST\}\}", $Script:Config.Network.WindowsIP
    $script = $script -replace "\{\{PROXY_PORT\}\}", $Script:Config.Network.ProxyPort

    # Save generated script
    $outputPath = Join-Path $Script:FridaScriptsDir "generated-ios-bypass.js"
    $script | Out-File -FilePath $outputPath -Encoding UTF8

    $Script:GeneratedScriptPath = $outputPath
    Write-Log "Generated bypass script for iOS $($VersionInfo.systemVersion)" "SUCCESS"

    return $outputPath
}

# Show main application menu
function Show-AppMenu {
    Clear-Host
    Show-Banner

    # Display current configuration
    if ($Script:SelectedIOSVersion) {
        Write-ColorOutput "  iOS VERSION BYPASS: ENABLED" "Green"
        Write-ColorOutput "  Spoofing as: $($Script:SelectedIOSVersion.displayName)" "Green"
        Write-ColorOutput "  CFNetwork: $($Script:SelectedIOSVersion.cfNetwork) | Darwin: $($Script:SelectedIOSVersion.darwin)" "DarkGreen"
    } else {
        Write-ColorOutput "  iOS VERSION BYPASS: DISABLED" "DarkYellow"
        Write-ColorOutput "  Using original device iOS version" "DarkYellow"
    }
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    Write-ColorOutput "  APP SELECTION MENU" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    Write-ColorOutput "  SPAWN MODE (App Restarts - Fresh Start):" "Yellow"
    Write-Host "  [1] DoorDash Dasher    - Restart with full control"
    Write-Host "  [2] DoorDash Dasher    - Alternative spawn method"
    Write-Host ""

    Write-ColorOutput "  ATTACH MODE (Stay Logged In):" "Green"
    Write-Host "  [3] DoorDash Dasher    - Keep current session"
    Write-Host ""

    Write-ColorOutput "  LIGHTWEIGHT MODE (Fast Performance):" "Magenta"
    Write-Host "  [4] DoorDash LIGHTWEIGHT - Minimal spoofing only" -ForegroundColor Magenta
    Write-Host ""

    Write-ColorOutput "  COMPREHENSIVE MODE (Enhanced API Compatibility):" "Yellow"
    Write-Host "  [5] DoorDash COMPREHENSIVE - Enhanced device fingerprinting (spawn)" -ForegroundColor Yellow
    Write-Host "  [6] DoorDash COMPREHENSIVE - Enhanced device fingerprinting (attach)" -ForegroundColor Yellow
    Write-Host ""

    Write-ColorOutput "  ANALYTICS FIX MODE (Resolves Version Inconsistency):" "Cyan"
    Write-Host "  [7] DoorDash ANALYTICS - JSON payload modification (spawn)" -ForegroundColor Cyan
    Write-Host "  [8] DoorDash ANALYTICS - JSON payload modification (attach)" -ForegroundColor Cyan
    Write-Host ""

    Write-ColorOutput "  iOS VERSION BYPASS:" "Cyan"
    Write-Host "  [V] Select iOS Version - Choose version to spoof (fix DoorDash)" -ForegroundColor Cyan
    Write-Host ""

    Write-ColorOutput "  OTHER OPTIONS:" "Cyan"
    Write-Host "  [R] RESET TO STOCK    - Remove all hooks/spoofing" -ForegroundColor Red
    Write-Host "  [C] Custom Bundle ID   - Enter any app"
    Write-Host "  [L] List Running Apps  - Show all processes"
    Write-Host "  [T] Test Connection    - Check Frida setup"
    Write-Host "  [S] SSH Tunnel         - Restart SSH connection"
    Write-Host "  [F] Frida Server       - Start on iPhone"
    Write-Host "  [H] Help              - Show usage guide"
    Write-Host "  [Q] Quit"
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    $selection = Read-Host "Select Option"

    # Process selection - FIXED to only use DoorDash
    switch ($selection.ToUpper()) {
        "1" {
            $appInfo = @{
                BundleID = $Script:Config.Apps.DoorDashDasher.BundleID
                Name = $Script:Config.Apps.DoorDashDasher.Name
            }
            Start-SpawnMode -AppInfo $appInfo
        }
        "2" {
            $appInfo = @{
                BundleID = $Script:Config.Apps.DoorDashDasher.BundleID
                Name = $Script:Config.Apps.DoorDashDasher.Name
            }
            Start-SpawnMode -AppInfo $appInfo
        }
        "3" {
            $appInfo = @{
                BundleID = $Script:Config.Apps.DoorDashDasher.BundleID
                Name = $Script:Config.Apps.DoorDashDasher.Name
            }
            Start-AttachMode -AppInfo $appInfo
        }
        "4" {
            # Lightweight DoorDash mode
            Write-Host ""
            Write-Host "  LIGHTWEIGHT MODE - Minimal Performance Impact" -ForegroundColor Magenta
            Write-Host ""
            $appInfo = @{
                BundleID = $Script:Config.Apps.DoorDashDasher.BundleID
                Name = $Script:Config.Apps.DoorDashDasher.Name
            }
            Start-LightweightMode -AppInfo $appInfo
        }
        "5" {
            # Comprehensive DoorDash mode (spawn)
            Write-Host ""
            Write-Host "  COMPREHENSIVE MODE - Enhanced Device Fingerprinting (SPAWN)" -ForegroundColor Yellow
            Write-Host ""
            $appInfo = @{
                BundleID = $Script:Config.Apps.DoorDashDasher.BundleID
                Name = $Script:Config.Apps.DoorDashDasher.Name
            }
            Start-ComprehensiveMode -AppInfo $appInfo -Mode "spawn"
        }
        "6" {
            # Comprehensive DoorDash mode (attach)
            Write-Host ""
            Write-Host "  COMPREHENSIVE MODE - Enhanced Device Fingerprinting (ATTACH)" -ForegroundColor Yellow
            Write-Host ""
            $appInfo = @{
                BundleID = $Script:Config.Apps.DoorDashDasher.BundleID
                Name = $Script:Config.Apps.DoorDashDasher.Name
            }
            Start-ComprehensiveMode -AppInfo $appInfo -Mode "attach"
        }
        "7" {
            # Analytics-aware DoorDash mode (spawn)
            Write-Host ""
            Write-Host "  ANALYTICS FIX MODE - JSON Payload Modification (SPAWN)" -ForegroundColor Cyan
            Write-Host "  This ensures 100% consistent iOS version reporting across ALL app components" -ForegroundColor Cyan
            Write-Host ""
            $appInfo = @{
                BundleID = $Script:Config.Apps.DoorDashDasher.BundleID
                Name = $Script:Config.Apps.DoorDashDasher.Name
            }
            Start-AnalyticsMode -AppInfo $appInfo -Mode "spawn"
        }
        "8" {
            # Analytics-aware DoorDash mode (attach)
            Write-Host ""
            Write-Host "  ANALYTICS FIX MODE - JSON Payload Modification (ATTACH)" -ForegroundColor Cyan
            Write-Host "  This ensures 100% consistent iOS version reporting across ALL app components" -ForegroundColor Cyan
            Write-Host ""
            $appInfo = @{
                BundleID = $Script:Config.Apps.DoorDashDasher.BundleID
                Name = $Script:Config.Apps.DoorDashDasher.Name
            }
            Start-AnalyticsMode -AppInfo $appInfo -Mode "attach"
        }
        "R" {
            # Reset to stock
            Start-ResetToStock
        }
        "V" {
            Show-IOSVersionMenu
            # Menu function will return here after selection
        }
        "C" { Start-CustomMode }
        "L" { Show-RunningApps; Show-AppMenu }
        "T" { Test-Connection; Show-AppMenu }
        "S" { Start-SSHTunnel; Show-AppMenu }
        "F" { Start-FridaServer; Show-AppMenu }
        "H" { Show-Help; Show-AppMenu }
        "Q" { Exit-Script }
        default {
            Write-Host "[!] Invalid selection" -ForegroundColor Red
            Start-Sleep -Seconds 1
            Show-AppMenu
        }
    }
}

# Start spawn mode - FIXED to handle null arguments properly
function Start-SpawnMode {
    param([hashtable]$AppInfo)

    Write-Host ""
    Write-ColorOutput "  SPAWN MODE - App will restart" "Yellow"
    Write-Host ""

    # Validate AppInfo
    if (-not $AppInfo -or -not $AppInfo.BundleID -or -not $AppInfo.Name) {
        Write-Host "[!] Error: Invalid app information" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    Write-Log "Starting fresh instance of $($AppInfo.Name)" "INFO"

    # Select appropriate script based on iOS version selection and app
    $scriptPath = $null
    if ($Script:SelectedIOSVersion) {
        # Use minimal safe bypass for DoorDash to prevent crashes
        if ($AppInfo.BundleID -eq "com.doordash.dasher") {
            $scriptPath = Join-Path $Script:FridaScriptsDir "doordash-minimal-safe.js"

            if (-not (Test-Path $scriptPath)) {
                # Fallback to lightweight script
                $scriptPath = Join-Path $Script:FridaScriptsDir "lightweight-spoof-only.js"
            }

            Write-Host "[+] Using MINIMAL SAFE DoorDash bypass (No Crashes)" -ForegroundColor Green
            Write-Host "[+] Spoofing as iOS $($Script:SelectedIOSVersion.systemVersion)" -ForegroundColor Cyan
            Write-Host "[+] Ultra-lightweight for stability!" -ForegroundColor Yellow
        } else {
            # Generate dynamic iOS bypass script with selected version for other apps
            $scriptPath = Generate-DynamicBypassScript -AppInfo $AppInfo
            if ($scriptPath) {
                Write-Host "[+] Generated iOS $($Script:SelectedIOSVersion.displayName) bypass with SSL pinning bypass" -ForegroundColor Green
                Write-Host "[+] Spoofing as iOS $($Script:SelectedIOSVersion.systemVersion)" -ForegroundColor Cyan
            } else {
                Write-Host "[!] Failed to generate bypass script, using default" -ForegroundColor Yellow
                $scriptPath = Join-Path $Script:FridaScriptsDir "ios-bypass-with-ssl.js"
            }
        }
    } else {
        # Use standard script if no iOS version selected
        $scriptPath = Join-Path $Script:FridaScriptsDir "enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js"
        if (-not (Test-Path $scriptPath)) {
            # Try alternative script
            $scriptPath = Join-Path $Script:FridaScriptsDir "universal-ssl-pinning-bypass-with-proxy.js"
        }
        Write-Host "[i] Using standard SSL bypass (no iOS version spoofing)" -ForegroundColor Yellow
    }

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[!] Script not found: $scriptPath" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    # Execute spawn
    Write-Host "Spawning $($AppInfo.Name)..." -ForegroundColor Cyan
    Write-Host "Bundle ID: $($AppInfo.BundleID)" -ForegroundColor DarkGray
    Write-Host "Script: $(Split-Path $scriptPath -Leaf)" -ForegroundColor DarkGray

    $pythonScript = Join-Path $Script:BaseDir "frida-spawn.py"

    # FIXED: Ensure arguments are not null
    $bundleId = $AppInfo.BundleID
    if ([string]::IsNullOrEmpty($bundleId)) {
        Write-Host "[!] Error: Bundle ID is empty" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    # Build arguments array - FIXED: Quote paths with spaces
    $arguments = @("`"$pythonScript`"", $bundleId, "`"$scriptPath`"")

    Show-InterceptionActive -AppInfo $AppInfo -Mode "SPAWN"

    # Start the process with Ctrl+C handling
    Write-Host ""
    Write-Host "Press Ctrl+C to stop interception and return to menu" -ForegroundColor Cyan
    Write-Host ""

    $exitCode = Start-ProcessWithCtrlC -FilePath "python" -ArgumentList $arguments

    if ($exitCode -eq $null) {
        # Ctrl+C was pressed, already handled
    } elseif ($exitCode -ne 0) {
        Write-Host "[!] Failed to spawn app (exit code: $exitCode)" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }

    Show-AppMenu
}

# Start attach mode - FIXED similarly
function Start-AttachMode {
    param([hashtable]$AppInfo)

    Write-Host ""
    Write-ColorOutput "  ATTACH MODE - Keep session" "Green"
    Write-Host ""

    # Validate AppInfo
    if (-not $AppInfo -or -not $AppInfo.BundleID -or -not $AppInfo.Name) {
        Write-Host "[!] Error: Invalid app information" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    # Find running process
    Write-Host "Looking for running $($AppInfo.Name)..." -ForegroundColor Cyan

    $processes = & python -c "import frida; d=frida.get_usb_device(); [print(f'{p.pid}:{p.name}') for p in d.enumerate_processes() if '$($AppInfo.BundleID)' in p.name.lower() or 'dasher' in p.name.lower()]" 2>$null

    if (-not $processes) {
        Write-Host "[!] App not running. Please open $($AppInfo.Name) first." -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    # Parse process info
    $processInfo = $processes[0] -split ':'
    $procId = $processInfo[0]
    $processName = $processInfo[1]

    Write-Host "[+] Found: $processName (PID: $procId)" -ForegroundColor Green

    # Generate bypass script if version selected
    $scriptPath = $null
    if ($Script:SelectedIOSVersion) {
        # Use the fixed iOS bypass script for attach mode too
        $scriptPath = Join-Path $Script:FridaScriptsDir "ios-bypass-with-ssl.js"
        Write-Host "[+] Using iOS $($Script:SelectedIOSVersion.displayName) bypass with SSL pinning bypass" -ForegroundColor Green
        Write-Host "[+] Spoofing as iOS $($Script:SelectedIOSVersion.systemVersion)" -ForegroundColor Cyan
    } else {
        # Use standard attach script if no iOS version selected
        $scriptPath = Join-Path $Script:FridaScriptsDir "attach-mode-proxy.js"
        if (-not (Test-Path $scriptPath)) {
            # Try alternative
            $scriptPath = Join-Path $Script:FridaScriptsDir "universal-ssl-pinning-bypass-with-proxy.js"
        }
        Write-Host "[i] Using standard SSL bypass (no iOS version spoofing)" -ForegroundColor Yellow
    }

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[!] Script not found: $scriptPath" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    # Execute attach
    Write-Host "Attaching to $processName..." -ForegroundColor Cyan
    $pythonScript = Join-Path $Script:BaseDir "frida-attach.py"

    # FIXED: Quote paths with spaces
    $arguments = @("`"$pythonScript`"", $procId, "`"$scriptPath`"")

    Show-InterceptionActive -AppInfo $AppInfo -Mode "ATTACH" -ProcessPID $procId

    # Start the process with Ctrl+C handling
    Write-Host ""
    Write-Host "Press Ctrl+C to stop interception and return to menu" -ForegroundColor Cyan
    Write-Host ""

    $exitCode = Start-ProcessWithCtrlC -FilePath "python" -ArgumentList $arguments

    if ($exitCode -eq $null) {
        # Ctrl+C was pressed, already handled
    } elseif ($exitCode -ne 0) {
        Write-Host "[!] Failed to attach to app (exit code: $exitCode)" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }

    Show-AppMenu
}

# Show interception active status
function Show-InterceptionActive {
    param(
        [hashtable]$AppInfo,
        [string]$Mode,
        [string]$ProcessPID
    )

    Write-Host ""

    if ($Mode -eq "ATTACH") {
        Write-ColorOutput "-----------------------------------------------------------------------------------------" "Green"
        Write-ColorOutput "                         INTERCEPTION ACTIVE - ATTACH MODE                              " "Green"
        Write-ColorOutput "                            [SESSION PRESERVED]                                         " "Green"
    } else {
        Write-ColorOutput "-----------------------------------------------------------------------------------------" "Yellow"
        Write-ColorOutput "                         INTERCEPTION ACTIVE - SPAWN MODE                               " "Yellow"
        Write-ColorOutput "                            [FRESH START]                                               " "Yellow"
    }

    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    Write-Host "  App:        $($AppInfo.Name)"
    Write-Host "  Bundle ID:  $($AppInfo.BundleID)"

    if ($ProcessPID) {
        Write-Host "  Process:    PID $ProcessPID"
    }

    if ($Script:SelectedIOSVersion) {
        Write-Host ""
        Write-ColorOutput "  iOS VERSION BYPASS ACTIVE:" "Green"
        Write-Host "  Spoofing:   $($Script:SelectedIOSVersion.displayName)" -ForegroundColor Cyan
        Write-Host "  iOS:        $($Script:SelectedIOSVersion.systemVersion)" -ForegroundColor Cyan
        Write-Host "  CFNetwork:  $($Script:SelectedIOSVersion.cfNetwork)" -ForegroundColor DarkCyan
        Write-Host "  Darwin:     $($Script:SelectedIOSVersion.darwin)" -ForegroundColor DarkCyan
    }

    Write-Host ""
    Write-Host "  Proxy:      $($Script:Config.Network.WindowsIP):$($Script:Config.Network.ProxyPort)"
    Write-Host ""
    Write-ColorOutput "  Traffic should now appear in HTTP Toolkit" "Cyan"
    Write-ColorOutput "  Press Ctrl+C to stop interception" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
}

# Show running apps
function Show-RunningApps {
    Write-Host ""
    Write-ColorOutput "  RUNNING PROCESSES" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"

    try {
        $output = & python -c "import frida; d=frida.get_usb_device(); apps=[p for p in d.enumerate_processes() if not p.name.startswith('kernel_') and 'SpringBoard' not in p.name]; [print(f'{p.pid:6} | {p.name}') for p in sorted(apps[:20], key=lambda x: x.name)]" 2>$null

        if ($output) {
            Write-Host $output
        } else {
            Write-Host "[!] No processes found or error occurred" -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Error listing processes: $_" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Test connection
function Test-Connection {
    Write-Host ""
    Write-ColorOutput "  TESTING FRIDA CONNECTION" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"

    try {
        $output = & python -c "import frida; d=frida.get_usb_device(); print(f'Device: {d.name}'); print(f'ID: {d.id}')" 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "[✓] Frida connection successful!" -ForegroundColor Green
            Write-Host $output
        } else {
            Write-Host "[!] Frida connection failed!" -ForegroundColor Red
            Write-Host $output
        }
    } catch {
        Write-Host "[!] Error testing connection: $_" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Show help
function Show-Help {
    Clear-Host
    Show-Banner

    Write-ColorOutput "  HELP & USAGE GUIDE" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    Write-ColorOutput "  iOS VERSION BYPASS:" "Cyan"
    Write-Host "  - Press [V] to select iOS version to spoof"
    Write-Host "  - DoorDash blocks iOS 16 and below"
    Write-Host "  - Use iOS 17.6.1 or 18.0 for best compatibility"
    Write-Host "  - CFNetwork version automatically matched to iOS version"
    Write-Host ""

    Write-ColorOutput "  SPAWN MODE vs ATTACH MODE:" "Cyan"
    Write-Host "  SPAWN MODE:  App restarts fresh (logs you out)"
    Write-Host "              Best for initial setup and testing"
    Write-Host "  ATTACH MODE: Keeps you logged in"
    Write-Host "              Best for staying in active dash"
    Write-Host ""

    Write-ColorOutput "  RECOMMENDATIONS:" "Yellow"
    Write-Host "  - DoorDash Dasher: Use iOS 17.6.1 or 18.0 bypass for best compatibility"
    Write-Host "  - Always check HTTP Toolkit is listening on port 8000"
    Write-Host "  - Use spawn mode for initial setup, attach mode to stay logged in"
    Write-Host ""

    Write-Host "Press any key to return..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Function to handle process with Ctrl+C support
function Start-ProcessWithCtrlC {
    param(
        [string]$FilePath,
        [array]$ArgumentList
    )

    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -PassThru

    try {
        while (!$process.HasExited) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::C -and $key.Modifiers -eq [ConsoleModifiers]::Control) {
                    Write-Host ""
                    Write-Host "[*] Ctrl+C detected - Stopping interception..." -ForegroundColor Yellow

                    # Try to gracefully stop the process
                    if (!$process.HasExited) {
                        $process.Kill()
                        Start-Sleep -Milliseconds 500
                    }

                    Write-Host "[+] Interception stopped. Returning to menu..." -ForegroundColor Green
                    Write-Host ""
                    return $null
                }
            }
            Start-Sleep -Milliseconds 100
        }

        # Process exited on its own
        return $process.ExitCode
    }
    catch {
        if (!$process.HasExited) {
            $process.Kill()
        }
        return -1
    }
}

# Exit handler
function Exit-Script {
    Write-Host ""

    # Clean up generated scripts
    if ($Script:GeneratedScriptPath -and (Test-Path $Script:GeneratedScriptPath)) {
        Remove-Item $Script:GeneratedScriptPath -Force -ErrorAction SilentlyContinue
    }

    # Kill plink processes
    Get-Process plink -ErrorAction SilentlyContinue | Stop-Process -Force

    Write-ColorOutput "Thank you for using FridaInterceptor Ultimate Enhanced!" "Cyan"
    Write-Host ""
    exit 0
}

# Start lightweight mode with minimal hooks
function Start-LightweightMode {
    param([hashtable]$AppInfo)

    # Validate AppInfo
    if (-not $AppInfo -or -not $AppInfo.BundleID -or -not $AppInfo.Name) {
        Write-Host "[!] Error: Invalid app information" -ForegroundColor Red
        Show-AppMenu
        return
    }

    Write-Host ""
    Write-Host "  LIGHTWEIGHT MODE - Minimal Hooks for Best Performance" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "[+] This mode only spoofs essential values:" -ForegroundColor Green
    Write-Host "    • iOS Version: 17.6.1" -ForegroundColor Gray
    Write-Host "    • CFNetwork: 1490.0.4 (Most important)" -ForegroundColor Yellow
    Write-Host "    • Darwin: 23.6.0" -ForegroundColor Gray
    Write-Host "    • App Version: 2.391.0 (if DoorDash)" -ForegroundColor Gray
    Write-Host ""

    # Use lightweight script
    $scriptPath = Join-Path $Script:FridaScriptsDir "lightweight-spoof-only.js"

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[!] Lightweight script not found!" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    Write-Host "Spawning $($AppInfo.Name) in LIGHTWEIGHT mode..." -ForegroundColor Cyan
    Write-Host "Bundle ID: $($AppInfo.BundleID)" -ForegroundColor Gray
    Write-Host "Script: lightweight-spoof-only.js" -ForegroundColor Gray
    Write-Host ""

    $pythonScript = Join-Path $Script:BaseDir "frida-spawn.py"
    $arguments = @("`"$pythonScript`"", $AppInfo.BundleID, "`"$scriptPath`"")

    # Start the process with Ctrl+C handling
    Write-Host "Press Ctrl+C to stop interception and return to menu" -ForegroundColor Cyan
    Write-Host ""

    $exitCode = Start-ProcessWithCtrlC -FilePath "python" -ArgumentList $arguments

    if ($exitCode -eq $null) {
        # Ctrl+C was pressed, already handled
    } elseif ($exitCode -ne 0) {
        Write-Host "[!] Failed to spawn app (exit code: $exitCode)" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }

    Show-AppMenu
}

# Start comprehensive mode with enhanced device fingerprinting
function Start-ComprehensiveMode {
    param(
        [hashtable]$AppInfo,
        [string]$Mode = "spawn"
    )

    # Validate AppInfo
    if (-not $AppInfo -or -not $AppInfo.BundleID -or -not $AppInfo.Name) {
        Write-Host "[!] Error: Invalid app information" -ForegroundColor Red
        Show-AppMenu
        return
    }

    Write-Host ""
    Write-Host "  COMPREHENSIVE MODE - Enhanced Device Fingerprinting" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  This mode addresses DoorDash API validation errors by spoofing:" -ForegroundColor Cyan
    Write-Host "  • Device model (iPhone 14 Pro)" -ForegroundColor Gray
    Write-Host "  • Hardware identifiers (iPhone15,3)" -ForegroundColor Gray
    Write-Host "  • System capabilities and kernel version" -ForegroundColor Gray
    Write-Host "  • Enhanced User-Agent with complete device info" -ForegroundColor Gray
    Write-Host "  • Basic anti-jailbreak detection bypass" -ForegroundColor Gray
    Write-Host "  • All values internally consistent with iOS 17.6.1" -ForegroundColor Gray
    Write-Host ""

    # Select appropriate script based on mode
    if ($Mode -eq "attach") {
        $scriptPath = Join-Path $Script:FridaScriptsDir "comprehensive-spoof-attach.js"
        Write-Host "  MODE: ATTACH (preserves login session)" -ForegroundColor Green
        Write-Host "  NOTE: Pull to refresh or navigate to activate proxy" -ForegroundColor Yellow
    } else {
        $scriptPath = Join-Path $Script:FridaScriptsDir "comprehensive-spoof-stable.js"
        Write-Host "  MODE: SPAWN (app restarts with fresh session)" -ForegroundColor Green
    }

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[!] Comprehensive script not found: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    Write-Host "Starting $($AppInfo.Name) in COMPREHENSIVE mode..." -ForegroundColor Yellow
    Write-Host "Bundle ID: $($AppInfo.BundleID)" -ForegroundColor Gray
    Write-Host "Script: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Gray
    Write-Host ""

    if ($Mode -eq "attach") {
        # Attach mode - find running process
        Write-Host "Looking for running $($AppInfo.Name)..." -ForegroundColor Cyan
        $fridaDevices = & python -c "import frida; d = frida.get_usb_device(); processes = d.enumerate_processes(); [print(f'{p.name}:{p.pid}') for p in processes if '$($AppInfo.BundleID)' in p.name.lower() or 'dasher' in p.name.lower()]" 2>$null
        $processes = $fridaDevices | Where-Object { $_ -and $_.Trim() -ne "" }

        if (-not $processes) {
            Write-Host "[!] App not running. Please open $($AppInfo.Name) first." -ForegroundColor Red
            Write-Host "Press any key to return..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-AppMenu
            return
        }

        $processInfo = $processes[0] -split ':'
        if ($processInfo.Length -ge 2) {
            $processName = $processInfo[0]
            $processId = $processInfo[1]
        } else {
            Write-Host "[!] Could not parse process information" -ForegroundColor Red
            Show-AppMenu
            return
        }

        Write-Host "Found: $processName (PID: $processId)" -ForegroundColor Green
        $pythonScript = Join-Path $Script:BaseDir "frida-attach.py"
        $arguments = @("`"$pythonScript`"", $processId, "`"$scriptPath`"")
    } else {
        # Spawn mode
        $pythonScript = Join-Path $Script:BaseDir "frida-spawn.py"
        $arguments = @("`"$pythonScript`"", $AppInfo.BundleID, "`"$scriptPath`"")
    }

    # Start the process with Ctrl+C handling
    Write-Host "Press Ctrl+C to stop interception and return to menu" -ForegroundColor Cyan
    Write-Host ""

    $exitCode = Start-ProcessWithCtrlC -FilePath "python" -ArgumentList $arguments

    if ($exitCode -eq $null) {
        # Ctrl+C was pressed, already handled
    } elseif ($exitCode -ne 0) {
        Write-Host "[!] Failed to start comprehensive mode (exit code: $exitCode)" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }

    Show-AppMenu
}

# Start Analytics mode - Ensures 100% consistent iOS version reporting
function Start-AnalyticsMode {
    param(
        [hashtable]$AppInfo,
        [string]$Mode = "spawn"
    )

    # Validate AppInfo
    if (-not $AppInfo -or -not $AppInfo.BundleID -or -not $AppInfo.Name) {
        Write-Host "[!] Error: Invalid app information" -ForegroundColor Red
        Show-AppMenu
        return
    }

    Write-Host ""
    Write-Host "  ANALYTICS FIX MODE - Complete Version Consistency" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This mode resolves API errors caused by inconsistent version reporting:" -ForegroundColor Yellow
    Write-Host "  • Hooks UIDevice and NSProcessInfo (Foundation APIs)" -ForegroundColor Gray
    Write-Host "  • Intercepts sysctlbyname for kernel/hardware info" -ForegroundColor Gray
    Write-Host "  • Modifies User-Agent headers in all requests" -ForegroundColor Gray
    Write-Host "  • CRITICAL: Hooks NSJSONSerialization to modify analytics payloads" -ForegroundColor Cyan
    Write-Host "  • Ensures ALL events report iOS 17.6.1 consistently" -ForegroundColor Green
    Write-Host ""

    # Use analytics script
    $scriptPath = Join-Path $Script:FridaScriptsDir "analytics-comprehensive-spoof.js"

    if ($Mode -eq "attach") {
        Write-Host "  MODE: ATTACH (preserves login session)" -ForegroundColor Green
        Write-Host "  NOTE: Pull to refresh or navigate to activate hooks" -ForegroundColor Yellow
    } else {
        Write-Host "  MODE: SPAWN (app restarts with fresh session)" -ForegroundColor Green
    }

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[!] Analytics script not found: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    Write-Host "Starting $($AppInfo.Name) in ANALYTICS FIX mode..." -ForegroundColor Cyan
    Write-Host "Bundle ID: $($AppInfo.BundleID)" -ForegroundColor Gray
    Write-Host "Script: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Gray
    Write-Host ""

    if ($Mode -eq "attach") {
        # Attach mode - find running process
        Write-Host "Looking for running $($AppInfo.Name)..." -ForegroundColor Cyan
        $pythonScript = Join-Path $Script:BaseDir "frida-attach.py"
        $processCmd = "python -c `"import frida; d = frida.get_usb_device(); processes = d.enumerate_processes(); [print(f'{p.name}:{p.pid}') for p in processes if '$($AppInfo.BundleID)' in p.identifier]`""

        try {
            $processInfo = Invoke-Expression $processCmd 2>$null | Select-Object -First 1
            if ($processInfo -match ":(\d+)$") {
                $pid = $matches[1]
                Write-Host "[✓] Found process with PID: $pid" -ForegroundColor Green
                Write-Host "Attaching analytics hooks..." -ForegroundColor Yellow

                $cmd = "python `"$pythonScript`" $pid `"$scriptPath`""
                Invoke-Expression $cmd
            } else {
                Write-Host "[!] App not running. Please start $($AppInfo.Name) first." -ForegroundColor Red
            }
        } catch {
            Write-Host "[!] Error finding process: $_" -ForegroundColor Red
        }
    } else {
        # Spawn mode
        Write-Host "App will restart with analytics hooks..." -ForegroundColor Yellow
        $pythonScript = Join-Path $Script:BaseDir "frida-spawn.py"

        $cmd = "python `"$pythonScript`" `"$($AppInfo.BundleID)`" `"$scriptPath`""
        Invoke-Expression $cmd
    }

    Write-Host ""
    Write-Host "[i] After testing, capture HAR file to verify all events show iOS 17.6.1" -ForegroundColor Yellow
    Write-Host "Press any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Reset device to stock (remove all hooks)
function Start-ResetToStock {
    Clear-Host
    Show-Banner

    Write-Host ""
    Write-ColorOutput "  RESET TO STOCK - Remove All Modifications" "Red"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    Write-Host "  This will:" -ForegroundColor Yellow
    Write-Host "  • Remove all Frida hooks" -ForegroundColor Gray
    Write-Host "  • Clear proxy configurations" -ForegroundColor Gray
    Write-Host "  • Restore original iOS behavior" -ForegroundColor Gray
    Write-Host "  • Detach from all apps" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Note: Some changes may persist until app restart" -ForegroundColor DarkGray
    Write-Host ""

    $confirm = Read-Host "  Are you sure you want to reset? (Y/N)"

    if ($confirm -eq "Y" -or $confirm -eq "y") {
        Write-Host ""
        Write-Host "[*] Starting reset process..." -ForegroundColor Cyan

        # Check for running Frida processes
        $processes = & python -c "import frida; d=frida.get_usb_device(); apps=['dasher','doordash']; [print(f'{p.pid}:{p.name}') for p in d.enumerate_processes() if any(a in p.name.lower() for a in apps)]" 2>$null

        if ($processes) {
            foreach ($proc in $processes) {
                if ($proc -match "(\d+):(.+)") {
                    $procId = $Matches[1]
                    $procName = $Matches[2]
                    Write-Host "[*] Found hooked app: $procName (PID: $procId)" -ForegroundColor Yellow

                    # Inject reset script
                    $resetScript = Join-Path $Script:FridaScriptsDir "reset-to-stock.js"
                    if (Test-Path $resetScript) {
                        $attachScript = Join-Path $Script:BaseDir "frida-attach.py"
                        $arguments = @("`"$attachScript`"", $procId, "`"$resetScript`"")

                        Write-Host "[*] Injecting reset script..." -ForegroundColor Cyan
                        $process = Start-Process -FilePath "python" -ArgumentList $arguments -NoNewWindow -PassThru -Wait

                        if ($process.ExitCode -eq 0) {
                            Write-Host "[+] Reset complete for $procName" -ForegroundColor Green
                        }
                    }
                }
            }
        } else {
            Write-Host "[*] No hooked apps found" -ForegroundColor Gray
        }

        Write-Host ""
        Write-Host "[+] RESET COMPLETE!" -ForegroundColor Green
        Write-Host "[+] Device restored to stock behavior" -ForegroundColor Green
        Write-Host ""
        Write-Host "  For complete reset:" -ForegroundColor Yellow
        Write-Host "  1. Force-quit any affected apps" -ForegroundColor Gray
        Write-Host "  2. Restart them normally" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Host "[*] Reset cancelled" -ForegroundColor Yellow
    }

    Write-Host "Press any key to return..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Custom mode
function Start-CustomMode {
    Write-Host ""
    Write-ColorOutput "  CUSTOM BUNDLE ID MODE" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    $bundleId = Read-Host "Enter Bundle ID (e.g., com.example.app)"

    if ([string]::IsNullOrWhiteSpace($bundleId)) {
        Write-Host "[!] Invalid Bundle ID" -ForegroundColor Red
        Start-Sleep -Seconds 1
        Show-AppMenu
        return
    }

    $customApp = @{
        BundleID = $bundleId
        Name = "Custom App ($bundleId)"
    }

    Write-Host ""
    Write-Host "Select mode:"
    Write-Host "[1] Spawn (restart app)"
    Write-Host "[2] Attach (keep session)"
    Write-Host "[B] Back"
    Write-Host ""

    $mode = Read-Host "Selection"

    switch ($mode) {
        "1" { Start-SpawnMode -AppInfo $customApp }
        "2" { Start-AttachMode -AppInfo $customApp }
        default { Show-AppMenu }
    }
}

# Start SSH tunnel (placeholder)
function Start-SSHTunnel {
    Write-Host ""
    Write-ColorOutput "  RESTARTING SSH TUNNEL" "Yellow"
    Write-Host ""

    # Kill existing plink
    Get-Process plink -ErrorAction SilentlyContinue | Stop-Process -Force

    # Start new tunnel
    $plinkPath = "plink.exe"
    $arguments = "-P 27042 -l root -pw alpine 127.0.0.1 -L 27042:127.0.0.1:22"

    Start-Process -FilePath $plinkPath -ArgumentList $arguments -WindowStyle Hidden

    Write-Host "[✓] SSH tunnel restarted" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Start Frida server (placeholder)
function Start-FridaServer {
    Write-Host ""
    Write-ColorOutput "  STARTING FRIDA SERVER" "Yellow"
    Write-Host ""

    try {
        $output = & plink -P 27042 -l root -pw alpine 127.0.0.1 "killall frida-server 2>/dev/null; /usr/sbin/frida-server -D &" 2>&1
        Write-Host "[✓] Frida server started" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to start Frida server: $_" -ForegroundColor Red
    }

    Start-Sleep -Seconds 2
}

# Main execution
try {
    # Initialize
    Initialize-Dependencies
    Load-Configuration
    Load-iOSVersionConfig

    # Debug: Show config loaded
    if ($Script:Debug) {
        Write-Host "Config Apps: $($Script:Config.Apps.Keys -join ', ')" -ForegroundColor Cyan
        Write-Host "DoorDash Bundle ID: $($Script:Config.Apps.DoorDashDasher.BundleID)" -ForegroundColor Cyan
    }

    # Create logs directory if needed
    if (-not (Test-Path $Script:LogDir)) {
        New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
    }

    # Show main menu
    Show-AppMenu

} catch {
    Write-Host "[!] Fatal error: $_" -ForegroundColor Red
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}