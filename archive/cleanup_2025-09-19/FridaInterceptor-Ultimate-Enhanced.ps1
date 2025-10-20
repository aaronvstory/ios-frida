# FridaInterceptor Ultimate v5.0 - Enhanced with iOS Version Bypass
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
                iOS18 = @{
                    displayName = "iOS 18.0 (Latest)"
                    systemVersion = "18.0"
                    cfNetwork = "1490.0.4"
                    darwin = "24.0.0"
                    buildNumber = "22A3354"
                    description = "Latest iOS version"
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

# Load configuration
function Load-Configuration {
    $configPath = Join-Path $Script:ConfigDir "frida-config.json"

    if (Test-Path $configPath) {
        try {
            $Script:Config = Get-Content $configPath -Raw | ConvertFrom-Json
            Write-Log "Configuration loaded from $configPath" "INFO"
        } catch {
            Write-Log "Error loading configuration: $_" "ERROR"
            Initialize-DefaultConfig
        }
    } else {
        Write-Log "Configuration file not found, using defaults" "WARNING"
        Initialize-DefaultConfig
    }
}

# Initialize default configuration
function Initialize-DefaultConfig {
    $Script:Config = @{
        Apps = @{
            doordash = @{
                Name = "DoorDash Dasher"
                BundleID = "com.doordash.dasher"
            }
            uber = @{
                Name = "Uber Driver"
                BundleID = "com.ubercab.driver"
            }
            lyft = @{
                Name = "Lyft Driver"
                BundleID = "com.lyft.driver"
            }
        }
        Network = @{
            WindowsIP = "192.168.50.9"
            iPhoneIP = "192.168.50.113"
            ProxyPort = 8000
            FridaPort = 27042
            SSHPort = 22
            SSHUser = "root"
            SSHPass = "alpine"
        }
    }
}

# Write log message
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"

    # Ensure log directory exists
    if (-not (Test-Path $Script:LogDir)) {
        New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
    }

    $logFile = Join-Path $Script:LogDir "frida-interceptor-$(Get-Date -Format 'yyyy-MM-dd').log"
    Add-Content -Path $logFile -Value $logMessage

    if ($Debug) {
        switch ($Level) {
            "ERROR" { Write-Host $logMessage -ForegroundColor Red }
            "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
            "INFO" { Write-Host $logMessage -ForegroundColor Cyan }
            "DEBUG" { Write-Host $logMessage -ForegroundColor Gray }
            default { Write-Host $logMessage }
        }
    }
}

# Color output helper
function Write-ColorOutput {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

# Display banner
function Show-Banner {
    $banner = @"

    ███████╗██████╗ ██╗██████╗  █████╗     ██╗   ██╗███████╗
    ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗    ██║   ██║██╔════╝
    █████╗  ██████╔╝██║██║  ██║███████║    ██║   ██║███████╗
    ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║    ╚██╗ ██╔╝╚════██║
    ██║     ██║  ██║██║██████╔╝██║  ██║     ╚████╔╝ ███████║
    ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝      ╚═══╝  ╚══════╝

              FridaInterceptor Ultimate $($Script:Version)
                 iOS Version Bypass Enhanced Edition

"@
    Write-ColorOutput $banner "Cyan"
}

# Show iOS version selection menu
function Show-iOSVersionMenu {
    param([string]$AppName = "")

    Clear-Host
    Show-Banner

    Write-ColorOutput "  iOS VERSION SELECTION" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"

    if ($AppName) {
        Write-Host "  App: $AppName" -ForegroundColor Cyan

        # Check for app-specific recommendations
        $appKey = $AppName.ToLower() -replace '\s+', ''
        if ($Script:iOSVersions.appRequirements.$appKey) {
            $req = $Script:iOSVersions.appRequirements.$appKey
            Write-Host "  ⚠️  $($req.notes)" -ForegroundColor Yellow
            Write-Host "  📱 Recommended: $($Script:iOSVersions.versions[$req.recommendedVersion].displayName)" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-ColorOutput "  SELECT iOS VERSION TO SPOOF:" "Cyan"
    Write-Host ""

    $versionKeys = @()
    $index = 1

    # Display available versions
    foreach ($key in $Script:iOSVersions.versions.Keys) {
        if ($key -ne "custom") {
            $version = $Script:iOSVersions.versions.$key
            $versionKeys += $key

            Write-Host "  [$index] $($version.displayName)" -ForegroundColor White
            Write-Host "       CFNetwork: $($version.cfNetwork) | Darwin: $($version.darwin)" -ForegroundColor DarkGray
            Write-Host "       $($version.description)" -ForegroundColor Gray
            Write-Host ""

            $index++
        }
    }

    Write-Host "  [C] Custom Version (Advanced)" -ForegroundColor Yellow
    Write-Host "  [D] Don't Spoof (Use Original)" -ForegroundColor DarkYellow
    Write-Host "  [B] Back to App Selection" -ForegroundColor Gray
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    $selection = Read-Host "Select iOS Version"

    switch ($selection.ToUpper()) {
        "C" {
            # Custom version input
            Write-Host ""
            Write-Host "Enter custom iOS version details:" -ForegroundColor Cyan
            $customVersion = Read-Host "iOS Version (e.g., 18.1)"
            $customCFNetwork = Read-Host "CFNetwork Version (e.g., 1494.0.7)"
            $customDarwin = Read-Host "Darwin Version (e.g., 24.1.0)"
            $customBuild = Read-Host "Build Number (e.g., 22B83)"

            $Script:SelectedIOSVersion = @{
                displayName = "Custom iOS $customVersion"
                systemVersion = $customVersion
                cfNetwork = $customCFNetwork
                darwin = $customDarwin
                buildNumber = $customBuild
                description = "User-defined custom version"
            }
            return $true
        }
        "D" {
            # No spoofing
            $Script:SelectedIOSVersion = $null
            Write-Host "[!] No iOS version spoofing selected" -ForegroundColor Yellow
            return $true
        }
        "B" {
            return $false
        }
        default {
            $num = 0
            if ([int]::TryParse($selection, [ref]$num)) {
                if ($num -ge 1 -and $num -le $versionKeys.Count) {
                    $selectedKey = $versionKeys[$num - 1]
                    $Script:SelectedIOSVersion = $Script:iOSVersions.versions.$selectedKey
                    Write-Host "[+] Selected: $($Script:SelectedIOSVersion.displayName)" -ForegroundColor Green
                    return $true
                }
            }
            Write-Host "[!] Invalid selection" -ForegroundColor Red
            Start-Sleep -Seconds 2
            return (Show-iOSVersionMenu -AppName $AppName)
        }
    }
}

# Generate dynamic JavaScript bypass script
function Generate-BypassScript {
    param([hashtable]$VersionInfo)

    if (-not $VersionInfo) {
        return $null
    }

    Write-Host "[+] Generating bypass script for $($VersionInfo.displayName)..." -ForegroundColor Cyan

    # Read template
    $templatePath = Join-Path $Script:FridaScriptsDir "ios-version-bypass-template.js"

    # If template doesn't exist, use embedded version
    if (-not (Test-Path $templatePath)) {
        Write-Host "[!] Template not found, creating default..." -ForegroundColor Yellow
        $template = Get-DefaultBypassTemplate
    } else {
        $template = Get-Content $templatePath -Raw
    }

    # Replace placeholders
    $script = $template -replace "{{VERSION}}", $VersionInfo.systemVersion
    $script = $script -replace "{{CFNETWORK}}", $VersionInfo.cfNetwork
    $script = $script -replace "{{DARWIN}}", $VersionInfo.darwin
    $script = $script -replace "{{BUILD}}", $VersionInfo.buildNumber
    $script = $script -replace "{{PROXY_HOST}}", $Script:Config.Network.WindowsIP
    $script = $script -replace "{{PROXY_PORT}}", $Script:Config.Network.ProxyPort.ToString()

    # Save generated script
    $outputPath = Join-Path $Script:FridaScriptsDir "generated-ios-bypass.js"
    Set-Content -Path $outputPath -Value $script -Encoding UTF8

    Write-Host "[+] Bypass script generated: $outputPath" -ForegroundColor Green

    return $outputPath
}

# Get default bypass template
function Get-DefaultBypassTemplate {
    return @'
// iOS Version Bypass - Generated
console.log("[+] iOS Version Bypass Active");
console.log("[+] Target: {{VERSION}} (CFNetwork {{CFNETWORK}})");

if (ObjC.available) {
    // UIDevice systemVersion
    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function (retval) {
                retval.replace(ObjC.classes.NSString.stringWithString_("{{VERSION}}"));
                console.log("[+] UIDevice.systemVersion -> {{VERSION}}");
            }
        });
    } catch (e) {}

    // User-Agent modification
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'].implementation, {
            onEnter: function (args) {
                var field = new ObjC.Object(args[3]).toString();
                if (field.toLowerCase() === "user-agent") {
                    var value = new ObjC.Object(args[2]).toString();
                    var newUA = value.replace(/iOS \d+\.\d+(\.\d+)?/, "iOS {{VERSION}}");
                    newUA = newUA.replace(/CFNetwork\/[\d.]+/, "CFNetwork/{{CFNETWORK}}");
                    newUA = newUA.replace(/Darwin\/[\d.]+/, "Darwin/{{DARWIN}}");
                    if (newUA !== value) {
                        args[2] = ObjC.classes.NSString.stringWithString_(newUA);
                        console.log("[+] User-Agent updated");
                    }
                }
            }
        });
    } catch (e) {}

    // Proxy configuration
    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration'].forEach(function(method) {
            var original = NSURLSessionConfiguration[method];
            if (original) {
                NSURLSessionConfiguration[method] = function() {
                    var config = original.call(this);
                    config.setConnectionProxyDictionary_({
                        "HTTPEnable": 1,
                        "HTTPProxy": "{{PROXY_HOST}}",
                        "HTTPPort": {{PROXY_PORT}},
                        "HTTPSEnable": 1,
                        "HTTPSProxy": "{{PROXY_HOST}}",
                        "HTTPSPort": {{PROXY_PORT}}
                    });
                    console.log("[+] Proxy configured: {{PROXY_HOST}}:{{PROXY_PORT}}");
                    return config;
                };
            }
        });
    } catch(e) {}

    // SSL bypass
    try {
        Interceptor.replace(Module.findExportByName(null, 'SecTrustEvaluate'), new NativeCallback(function(trust, result) {
            Memory.writePointer(result, ptr(0x1));
            return 0;
        }, 'int', ['pointer', 'pointer']));
    } catch(e) {}
}

console.log("[+] Bypass ready!");
'@
}

# Show app selection menu
function Show-AppMenu {
    param([switch]$SkipBanner)

    if (-not $SkipBanner) {
        Clear-Host
        Show-Banner
    }

    Write-ColorOutput "  APP SELECTION MENU" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    Write-ColorOutput "  SPAWN MODE (App Restarts - Logs You Out):" "Yellow"
    Write-Host "  [1] DoorDash Dasher    - Fresh start with bypass"
    Write-Host "  [2] Uber Driver        - Fresh start with bypass"
    Write-Host "  [3] Lyft Driver        - Fresh start with bypass"
    Write-Host ""

    Write-ColorOutput "  ATTACH MODE (Stay Logged In):" "Green"
    Write-Host "  [4] DoorDash Dasher    - Attach to running app"
    Write-Host "  [5] Uber Driver        - Attach to running app"
    Write-Host "  [6] Lyft Driver        - Attach to running app"
    Write-Host ""

    Write-ColorOutput "  OTHER OPTIONS:" "Cyan"
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

    # Process selection
    switch ($selection.ToUpper()) {
        "1" {
            $app = $Script:Config.Apps.doordash
            if (Show-iOSVersionMenu -AppName $app.Name) {
                Start-SpawnMode -AppInfo $app
            } else {
                Show-AppMenu
            }
        }
        "2" {
            $app = $Script:Config.Apps.uber
            if (Show-iOSVersionMenu -AppName $app.Name) {
                Start-SpawnMode -AppInfo $app
            } else {
                Show-AppMenu
            }
        }
        "3" {
            $app = $Script:Config.Apps.lyft
            if (Show-iOSVersionMenu -AppName $app.Name) {
                Start-SpawnMode -AppInfo $app
            } else {
                Show-AppMenu
            }
        }
        "4" {
            $app = $Script:Config.Apps.doordash
            if (Show-iOSVersionMenu -AppName $app.Name) {
                Start-AttachMode -AppInfo $app
            } else {
                Show-AppMenu
            }
        }
        "5" {
            $app = $Script:Config.Apps.uber
            if (Show-iOSVersionMenu -AppName $app.Name) {
                Start-AttachMode -AppInfo $app
            } else {
                Show-AppMenu
            }
        }
        "6" {
            $app = $Script:Config.Apps.lyft
            if (Show-iOSVersionMenu -AppName $app.Name) {
                Start-AttachMode -AppInfo $app
            } else {
                Show-AppMenu
            }
        }
        "C" {
            Write-Host ""
            $customBundle = Read-Host "Enter Bundle ID (e.g., com.example.app)"

            $customApp = @{
                BundleID = $customBundle
                Name = $customBundle
            }

            Write-Host ""
            $mode = Read-Host "Use [S]pawn or [A]ttach mode?"

            if (Show-iOSVersionMenu -AppName $customBundle) {
                if ($mode -eq "A" -or $mode -eq "a") {
                    Start-AttachMode -AppInfo $customApp
                } else {
                    Start-SpawnMode -AppInfo $customApp
                }
            } else {
                Show-AppMenu
            }
        }
        "L" { Show-RunningApps }
        "T" { Test-FridaConnection }
        "S" { Start-SSHTunnel; Show-AppMenu }
        "F" { Start-FridaServerOnDevice; Show-AppMenu }
        "H" { Show-Help }
        "Q" { Exit-Script }
        default {
            Write-Host "[!] Invalid selection" -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-AppMenu
        }
    }
}

# Start spawn mode
function Start-SpawnMode {
    param([hashtable]$AppInfo)

    Write-Host ""
    Write-ColorOutput "  SPAWN MODE - App will restart" "Yellow"
    Write-Host ""
    Write-Log "Starting fresh instance of $($AppInfo.Name)" "INFO"

    # Generate bypass script if version selected
    $scriptPath = $null
    if ($Script:SelectedIOSVersion) {
        $scriptPath = Generate-BypassScript -VersionInfo $Script:SelectedIOSVersion
    } else {
        # Use standard script
        $scriptPath = Join-Path $Script:FridaScriptsDir "enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js"
    }

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[!] Script not found: $scriptPath" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    Show-InterceptionBanner -AppInfo $AppInfo -Mode "SPAWN"

    # Execute spawn
    Write-Host "[+] Spawning $($AppInfo.BundleID) with bypass..." -ForegroundColor Green

    $spawnScript = Join-Path $Script:BaseDir "frida-spawn.py"
    & python $spawnScript $AppInfo.BundleID $scriptPath 2>&1 | ForEach-Object {
        if ($_ -match "ERROR") {
            Write-ColorOutput $_ "Red"
        } elseif ($_ -match "\[\+\]") {
            Write-ColorOutput $_ "Green"
        } else {
            Write-Host $_
        }
    }

    Write-Host ""
    Write-Host "Press any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Start attach mode
function Start-AttachMode {
    param([hashtable]$AppInfo)

    Write-Host ""
    Write-ColorOutput "  ATTACH MODE - Keep session" "Green"
    Write-Host ""

    # Find running process
    Write-Host "Looking for running $($AppInfo.Name)..." -ForegroundColor Cyan

    $processes = & python -c "import frida; d=frida.get_usb_device(); [print(f'{p.pid}:{p.name}') for p in d.enumerate_processes() if '$($AppInfo.BundleID)' in p.name.lower() or any(x in p.name.lower() for x in ['dasher', 'uber', 'lyft'])]" 2>$null

    if (-not $processes) {
        Write-Host "[!] App not running. Please open $($AppInfo.Name) first." -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    # Parse process info
    $processInfo = $processes[0] -split ':'
    $pid = $processInfo[0]
    $processName = $processInfo[1]

    Write-Host "[+] Found: $processName (PID: $pid)" -ForegroundColor Green

    # Generate bypass script if version selected
    $scriptPath = $null
    if ($Script:SelectedIOSVersion) {
        $scriptPath = Generate-BypassScript -VersionInfo $Script:SelectedIOSVersion
    } else {
        # Use standard script
        $scriptPath = Join-Path $Script:FridaScriptsDir "attach-mode-proxy.js"
    }

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[!] Script not found: $scriptPath" -ForegroundColor Red
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }

    Show-InterceptionBanner -AppInfo $AppInfo -Mode "ATTACH" -ProcessPID $pid

    # Execute attach
    Write-Host "[+] Attaching to PID $pid..." -ForegroundColor Green

    $attachScript = Join-Path $Script:BaseDir "frida-attach.py"
    & python $attachScript $pid $scriptPath 2>&1 | ForEach-Object {
        if ($_ -match "ERROR") {
            Write-ColorOutput $_ "Red"
        } elseif ($_ -match "\[\+\]") {
            Write-ColorOutput $_ "Green"
        } else {
            Write-Host $_
        }
    }

    Write-Host ""
    Write-Host "Press any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Test Frida connection
function Test-FridaConnection {
    Clear-Host
    Show-Banner

    Write-ColorOutput "  TESTING FRIDA CONNECTION" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    Write-Host "Testing USB connection..." -ForegroundColor Cyan

    $testResult = & python -c "
import frida
try:
    device = frida.get_usb_device()
    print(f'[+] Connected to: {device.name}')
    print(f'[+] Device ID: {device.id}')
    processes = device.enumerate_processes()
    print(f'[+] Found {len(processes)} processes')
    print('[+] Connection successful!')
except Exception as e:
    print(f'[-] Error: {e}')
" 2>&1

    $testResult | ForEach-Object {
        if ($_ -match "\[\+\]") {
            Write-ColorOutput $_ "Green"
        } elseif ($_ -match "\[-\]") {
            Write-ColorOutput $_ "Red"
        } else {
            Write-Host $_
        }
    }

    Write-Host ""
    Write-Host "Press any key to return..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Show running apps
function Show-RunningApps {
    Write-Host ""
    Write-ColorOutput "  RUNNING APPS ON IPHONE" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    $processes = & python -c "
import frida
device = frida.get_usb_device()
for p in device.enumerate_processes():
    if p.pid > 0 and not p.name.startswith('kernel'):
        print(f'  {p.pid:6} | {p.name}')
" 2>&1 | Select-Object -First 30

    Write-ColorOutput "  PID    | NAME" "Cyan"
    Write-Host "  -------|--------------------"
    $processes | ForEach-Object { Write-Host $_ }

    Write-Host ""
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Start SSH tunnel
function Start-SSHTunnel {
    Write-Host "Starting SSH tunnel..." -ForegroundColor Cyan

    # Use plink for SSH tunnel
    $plinkPath = Join-Path $Script:BaseDir "plink.exe"
    if (-not (Test-Path $plinkPath)) {
        Write-Host "[!] plink.exe not found, downloading..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" -OutFile $plinkPath
    }

    # Kill existing plink processes
    Get-Process plink -ErrorAction SilentlyContinue | Stop-Process -Force

    # Start new tunnel
    $sshArgs = @(
        "-batch",
        "-pw", $Script:Config.Network.SSHPass,
        "-P", "22",
        "-l", $Script:Config.Network.SSHUser,
        "127.0.0.1",
        "-L", "27042:127.0.0.1:27042"
    )

    Start-Process -FilePath $plinkPath -ArgumentList $sshArgs -WindowStyle Hidden

    Write-Host "[+] SSH tunnel started" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Start frida-server on device
function Start-FridaServerOnDevice {
    Write-Host "Starting frida-server on iPhone..." -ForegroundColor Cyan

    $plinkPath = Join-Path $Script:BaseDir "plink.exe"

    $result = & $plinkPath -batch -pw $Script:Config.Network.SSHPass root@127.0.0.1 "killall frida-server 2>/dev/null; frida-server &" 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] frida-server started" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] Failed to start frida-server" -ForegroundColor Red
        return $false
    }
}

# Display interception banner
function Show-InterceptionBanner {
    param(
        [hashtable]$AppInfo,
        [string]$Mode,
        [string]$ProcessPID = ""
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
        Write-Host "  iOS Spoof:  $($Script:SelectedIOSVersion.displayName)" -ForegroundColor Cyan
        Write-Host "  CFNetwork:  $($Script:SelectedIOSVersion.cfNetwork)" -ForegroundColor DarkCyan
    }
    Write-Host "  Proxy:      $($Script:Config.Network.WindowsIP):$($Script:Config.Network.ProxyPort)"
    Write-Host ""
    Write-ColorOutput "  Traffic should now appear in HTTP Toolkit" "Cyan"
    Write-ColorOutput "  Press Ctrl+C to stop interception" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
}

# Show help
function Show-Help {
    Clear-Host
    Show-Banner

    Write-ColorOutput "  HELP - ENHANCED VERSION WITH iOS BYPASS" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""

    Write-ColorOutput "  iOS VERSION SPOOFING:" "Cyan"
    Write-Host "  - Select iOS version to bypass app restrictions"
    Write-Host "  - CFNetwork version automatically matched"
    Write-Host "  - Darwin kernel version properly spoofed"
    Write-Host "  - User-Agent headers modified in all requests"
    Write-Host ""

    Write-ColorOutput "  RECOMMENDED VERSIONS:" "Green"
    Write-Host "  - DoorDash: iOS 17.6.1 or 18.0 (blocks iOS 16)"
    Write-Host "  - Uber/Lyft: Any version usually works"
    Write-Host ""

    Write-ColorOutput "  TWO MODES:" "Yellow"
    Write-Host "  SPAWN MODE: Restarts app fresh (logs out)"
    Write-Host "  ATTACH MODE: Keeps you logged in"
    Write-Host ""

    Write-Host "Press any key to return..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Exit handler
function Exit-Script {
    Write-Host ""

    # Clean up
    Get-Process plink -ErrorAction SilentlyContinue | Stop-Process -Force

    # Delete generated scripts
    if ($Script:GeneratedScriptPath -and (Test-Path $Script:GeneratedScriptPath)) {
        Remove-Item $Script:GeneratedScriptPath -Force
    }

    Write-ColorOutput "Thank you for using FridaInterceptor Ultimate Enhanced!" "Cyan"
    Write-Host ""
    exit 0
}

# Main execution
function Main {
    # Initialize
    Initialize-Dependencies
    Load-Configuration
    Load-iOSVersionConfig

    # Create necessary directories
    @($Script:LogDir, $Script:FridaScriptsDir, $Script:ConfigDir) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }

    # Start SSH tunnel
    Start-SSHTunnel

    # Show menu
    Show-AppMenu
}

# Run main
Main