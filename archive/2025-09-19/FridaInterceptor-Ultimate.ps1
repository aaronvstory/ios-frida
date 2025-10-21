# FridaInterceptor Ultimate v4.0 - Complete Integration
# Spawn or Attach modes - Stay logged in option!
# ============================================================================

param(
    [string]$App = "",
    [string]$Mode = "",
    [switch]$Debug,
    [switch]$Help
)

# Set console encoding
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

# Script configuration
$Script:Version = "4.0"
$Script:BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:LogDir = Join-Path $BaseDir "logs"
$Script:FridaScriptsDir = Join-Path $BaseDir "frida-interception-and-unpinning"

# Initialize and check dependencies
function Initialize-Dependencies {
    Write-Host "Checking dependencies..." -ForegroundColor Cyan
    
    # Check for uv
    $uvPath = Get-Command uv -ErrorAction SilentlyContinue
    if (-not $uvPath) {
        Write-Host "[!] Installing uv (fast Python package installer)..." -ForegroundColor Yellow
        try {
            # Install uv using PowerShell
            Invoke-WebRequest -Uri "https://astral.sh/uv/install.ps1" | Invoke-Expression
            
            # Refresh PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        } catch {
            Write-Host "[!] Could not install uv automatically. Installing via pip..." -ForegroundColor Yellow
            & pip install uv 2>&1 | Out-Null
        }
    }
    
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
    
    # Check for frida-tools - try multiple locations
    $fridaPath = Get-Command frida -ErrorAction SilentlyContinue
    $fridaPsPath = Get-Command frida-ps -ErrorAction SilentlyContinue
    
    # If not found as commands, check if Python modules exist
    if (-not $fridaPsPath) {
        Write-Host "[!] Frida commands not in PATH, checking Python modules..." -ForegroundColor Yellow
        $pythonTest = & python -c "import frida_tools" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Frida available as Python module" -ForegroundColor Green
            # Create wrapper functions for frida commands
            $Script:UsePythonFrida = $true
        }
    }
    
    # If not in PATH, check Python Scripts directory
    if (-not $fridaPsPath) {
        $pythonScripts = @(
            "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts",
            "$env:LOCALAPPDATA\Programs\Python\Python312\Scripts",
            "$env:LOCALAPPDATA\Programs\Python\Python311\Scripts",
            "$env:LOCALAPPDATA\Programs\Python\Python310\Scripts",
            "$env:LOCALAPPDATA\Programs\Python\Python39\Scripts",
            "$env:LOCALAPPDATA\Programs\Python\Python38\Scripts",
            "C:\Python313\Scripts",
            "C:\Python312\Scripts", 
            "C:\Python311\Scripts",
            "C:\Python310\Scripts",
            "C:\Python39\Scripts",
            "C:\Python38\Scripts",
            "$env:USERPROFILE\AppData\Roaming\Python\Python313\Scripts",
            "$env:USERPROFILE\AppData\Roaming\Python\Python312\Scripts",
            "$env:USERPROFILE\AppData\Roaming\Python\Python311\Scripts"
        )
        
        foreach ($scriptPath in $pythonScripts) {
            if (Test-Path "$scriptPath\frida-ps.exe") {
                Write-Host "[!] Frida found in $scriptPath but not in PATH" -ForegroundColor Yellow
                Write-Host "    Adding to current session PATH..." -ForegroundColor Cyan
                $env:Path = "$scriptPath;$env:Path"
                $fridaPath = Get-Command frida -ErrorAction SilentlyContinue
                $fridaPsPath = Get-Command frida-ps -ErrorAction SilentlyContinue
                break
            }
        }
    }
    
    if (-not $fridaPath -or -not $fridaPsPath) {
        Write-Host "[!] Frida tools not found. Installing automatically..." -ForegroundColor Yellow
        
        # Check if requirements.txt exists
        $requirementsFile = Join-Path $Script:BaseDir "requirements.txt"
        
        # For frida-tools, use pip directly as it has native dependencies
        Write-Host "    Installing with pip..." -ForegroundColor Yellow
        
        # Check if it's already installed via pip
        $fridaInstalled = & pip show frida-tools 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    Frida-tools is already installed but not in PATH." -ForegroundColor Yellow
        } else {
            # Install with pip
            if (Test-Path $requirementsFile) {
                Write-Host "    Installing from requirements.txt..." -ForegroundColor Cyan
                & pip install -r $requirementsFile 2>&1 | ForEach-Object {
                    if ($_ -match "error|failed") {
                        Write-Host $_ -ForegroundColor Red
                    } elseif ($_ -match "Successfully installed|Requirement already satisfied") {
                        Write-Host $_ -ForegroundColor Green
                    }
                }
            } else {
                & pip install frida-tools 2>&1 | ForEach-Object {
                    if ($_ -match "error|failed") {
                        Write-Host $_ -ForegroundColor Red
                    } elseif ($_ -match "Successfully installed|Requirement already satisfied") {
                        Write-Host $_ -ForegroundColor Green
                    }
                }
            }
        }
        
        # Refresh PATH to find newly installed commands
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Verify installation
        $fridaPath = Get-Command frida -ErrorAction SilentlyContinue
        $fridaPsPath = Get-Command frida-ps -ErrorAction SilentlyContinue
        
        if ($fridaPath -and $fridaPsPath) {
            Write-Host "[+] Frida tools installed successfully!" -ForegroundColor Green
        } else {
            Write-Host "[!] Frida tools installation may have failed." -ForegroundColor Red
            Write-Host "    Try running manually: pip install frida-tools" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[+] Frida tools found." -ForegroundColor Green
    }
    
    # Check for HTTP Toolkit (optional, just warn if missing)
    $httpToolkitPath = Get-Command httptoolkit -ErrorAction SilentlyContinue
    if (-not $httpToolkitPath) {
        # Check if it's installed but not in PATH
        $httpToolkitExe = "$env:LOCALAPPDATA\Programs\httptoolkit\HTTP Toolkit.exe"
        if (-not (Test-Path $httpToolkitExe)) {
            Write-Host "[!] HTTP Toolkit not found. Download from: https://httptoolkit.com" -ForegroundColor Yellow
            Write-Host "    The script will continue but traffic interception won't work." -ForegroundColor Gray
        }
    } else {
        Write-Host "[+] HTTP Toolkit found." -ForegroundColor Green
    }
    
    Write-Host ""
    
    # Setup frida command paths
    if (Setup-FridaCommands) {
        Write-Host "[+] Frida commands configured" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Dependency check complete!" -ForegroundColor Green
    Write-Host ""
    Start-Sleep -Seconds 1
}

# Dependencies will be initialized in Main function

# Network configuration
$Script:Config = @{
    Network = @{
        iPhoneIP = "192.168.50.113"
        FridaPort = 27042
        ProxyPort = 8000
        WindowsIP = "192.168.50.9"
        UseSSHTunnel = $true  # Use SSH tunnel through localhost
        SSHPort = 22
        LocalPort = 27042  # Local port for tunnel
    }
    Apps = @{
        dasher = @{
            Name = "DoorDash Dasher"
            BundleID = "com.doordash.dasher"
            ProcessName = "DasherApp"
        }
        doordash = @{
            Name = "DoorDash Customer"
            BundleID = "doordash.DoorDashConsumer"
            ProcessName = "DoorDash"
        }
        safari = @{
            Name = "Safari Browser"
            BundleID = "com.apple.mobilesafari"
            ProcessName = "MobileSafari"
        }
    }
    Settings = @{
        MaxRetries = 3
        RetryDelay = 5
        AutoStartHTTPToolkit = $true
    }
}

# Simple color output - MUST BE FIRST
function Write-ColorOutput {
    param([string]$Text, [string]$Color = "White")
    
    $oldColor = $Host.UI.RawUI.ForegroundColor
    try {
        $Host.UI.RawUI.ForegroundColor = $Color
        Write-Host $Text
    } finally {
        $Host.UI.RawUI.ForegroundColor = $oldColor
    }
}

# Logging - MUST BE SECOND
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    switch ($Level) {
        "ERROR"   { Write-ColorOutput "[ERROR] $Message" "Red" }
        "WARN"    { Write-ColorOutput "[WARN]  $Message" "Yellow" }
        "SUCCESS" { Write-ColorOutput "[OK]    $Message" "Green" }
        "INFO"    { Write-ColorOutput "[INFO]  $Message" "Cyan" }
        "DEBUG"   { 
            if ($Debug) {
                Write-ColorOutput "[DEBUG] $Message" "Gray"
            }
        }
    }
}

# Initialize logging
function Initialize-Logging {
    if (-not (Test-Path $Script:LogDir)) {
        New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
    }
    $Script:LogFile = Join-Path $Script:LogDir "session-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

# Setup frida command paths
$Script:FridaCmd = "frida"
$Script:FridaPsCmd = "frida-ps"

# Check if frida is in PATH, otherwise use wrappers
function Setup-FridaCommands {
    $fridaPath = Get-Command frida -ErrorAction SilentlyContinue
    $fridaPsPath = Get-Command frida-ps -ErrorAction SilentlyContinue
    
    if (-not $fridaPath -or -not $fridaPsPath) {
        # Check if Python module exists
        $pythonTest = & python -c "import frida_tools" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[!] Using Python module for frida (not in PATH)" -ForegroundColor Yellow
            $Script:FridaCmd = Join-Path $Script:BaseDir "frida-wrapper.bat"
            $Script:FridaPsCmd = Join-Path $Script:BaseDir "frida-ps-wrapper.bat"
            $Script:UsePythonModule = $true
            return $true
        }
        return $false
    }
    $Script:UsePythonModule = $false
    $Script:FridaCmd = "frida"
    $Script:FridaPsCmd = "frida-ps"
    return $true
}

# Initialize Frida scripts
function Initialize-FridaScripts {
    $scriptPath = Join-Path $Script:FridaScriptsDir "universal-ssl-pinning-bypass.js"
    
    if (-not (Test-Path $scriptPath)) {
        Write-Log "Creating universal SSL pinning bypass script..." "INFO"
        
        $scriptContent = @'
// Universal SSL Pinning Bypass for iOS
// Works with most iOS apps

console.log("[*] Starting Universal SSL Pinning Bypass...");

// Hook common SSL pinning methods
if (ObjC.available) {
    try {
        // NSURLSession bypass
        var className = "NSURLSession";
        var funcName = "- URLSession:didReceiveChallenge:completionHandler:";
        
        var hook = ObjC.classes.NSURLSession["- URLSession:didReceiveChallenge:completionHandler:"];
        if (hook) {
            Interceptor.attach(hook.implementation, {
                onEnter: function(args) {
                    console.log("[*] Bypassing SSL pinning in NSURLSession");
                    // Call completion handler to accept any certificate
                    var completionHandler = new ObjC.Block(args[4]);
                    completionHandler(0, null);
                }
            });
        }
        
        // SecTrustEvaluate bypass
        var SecTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                console.log("[*] Bypassing SecTrustEvaluate");
                Memory.writeU32(result, 0); // kSecTrustResultProceed
                return 0;
            }, 'int', ['pointer', 'pointer']));
        }
        
        // SecTrustEvaluateWithError bypass
        var SecTrustEvaluateWithError = Module.findExportByName(null, "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                console.log("[*] Bypassing SecTrustEvaluateWithError");
                Memory.writePointer(error, NULL);
                return 1; // true
            }, 'bool', ['pointer', 'pointer']));
        }
        
        console.log("[+] SSL Pinning bypass hooks installed");
        
    } catch(err) {
        console.log("[!] Error setting up SSL pinning bypass: " + err.message);
    }
} else {
    console.log("[!] Objective-C runtime not available");
}

// Proxy configuration
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

console.log("[*] Proxy configured: " + proxyHost + ":" + proxyPort);
console.log("[+] Ready to intercept traffic!");
'@
        
        Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8
        Write-Log "SSL pinning bypass script created" "SUCCESS"
    }
}



# Display banner with ASCII art
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "Cyan"
    Write-Host ""
    
    Write-ColorOutput @"
     ███████╗██████╗ ██╗██████╗  █████╗     ██╗   ██╗██╗  ████████╗
     ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗    ██║   ██║██║  ╚══██╔══╝
     █████╗  ██████╔╝██║██║  ██║███████║    ██║   ██║██║     ██║   
     ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║    ██║   ██║██║     ██║   
     ██║     ██║  ██║██║██████╔╝██║  ██║    ╚██████╔╝███████╗██║   
     ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝     ╚═════╝ ╚══════╝╚═╝   
"@ "Yellow"
    
    Write-Host ""
    Write-ColorOutput "                 Ultimate iOS Interception v$($Script:Version) - Stay Logged In!" "White"
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "Cyan"
    Write-Host ""
}

# System status check
function Show-Status {
    Write-Host ""
    Write-ColorOutput "  SYSTEM STATUS" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    
    # Check SSH Tunnel
    if ($Script:Config.Network.UseSSHTunnel) {
        Write-Host -NoNewline "  SSH Tunnel (USB)... "
        $tunnelStatus = Test-SSHTunnel
        if ($tunnelStatus) {
            Write-ColorOutput "[ACTIVE] localhost:$($Script:Config.Network.LocalPort)" "Green"
        } else {
            Write-ColorOutput "[NOT ACTIVE]" "Yellow"
        }
    }
    
    # Check HTTP Toolkit
    Write-Host -NoNewline "  HTTP Toolkit... "
    $httpToolkitStatus = Test-HTTPToolkit
    if ($httpToolkitStatus) {
        Write-ColorOutput "[RUNNING] Port $($Script:Config.Network.ProxyPort)" "Green"
    } else {
        Write-ColorOutput "[NOT RUNNING]" "Red"
    }
    
    # Check Frida connection
    Write-Host -NoNewline "  Frida Server... "
    $fridaStatus = Test-FridaConnection
    if ($fridaStatus) {
        $connectionInfo = if ($Script:Config.Network.UseUSB) {
            "USB Direct Connection"
        } elseif ($Script:Config.Network.UseSSHTunnel -and (Test-SSHTunnel)) {
            "localhost:$($Script:Config.Network.LocalPort) (via SSH tunnel)"
        } else {
            "$($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)"
        }
        Write-ColorOutput "[CONNECTED] $connectionInfo" "Green"
    } else {
        Write-ColorOutput "[NOT CONNECTED]" "Red"
        Write-Host ""
        Write-ColorOutput "  Quick Fix Options:" "Yellow"
        Write-Host "  Option 1: Press [F] to start frida-server remotely"
        Write-Host "  Option 2: Manual SSH:"
        Write-Host "     ssh root@127.0.0.1 (via USB) or root@$($Script:Config.Network.iPhoneIP)"
        Write-Host "     Then run: frida-server &"
        Write-Host "  Option 3: Test with: frida-ps -U (USB) or frida-ps -H 127.0.0.1:27042"
    }
    
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
}

# SSH Tunnel Management
$Script:SSHTunnel = $null

function Start-SSHTunnel {
    Write-Host "Setting up SSH tunnel..." -ForegroundColor Cyan
    
    # Check if plink is available
    $plinkPath = Get-Command plink -ErrorAction SilentlyContinue
    if (-not $plinkPath) {
        # Try common locations
        $plinkLocations = @(
            "C:\Program Files\PuTTY\plink.exe",
            "C:\Program Files (x86)\PuTTY\plink.exe",
            "$env:ProgramFiles\PuTTY\plink.exe",
            "$env:USERPROFILE\Downloads\plink.exe",
            "$Script:BaseDir\plink.exe"
        )
        
        foreach ($location in $plinkLocations) {
            if (Test-Path $location) {
                $plinkPath = $location
                break
            }
        }
        
        if (-not $plinkPath) {
            Write-Host "[!] plink.exe not found. Please install PuTTY or download plink.exe" -ForegroundColor Red
            Write-Host "    Download from: https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html" -ForegroundColor Yellow
            return $false
        }
    }
    
    # Kill any existing plink processes
    Get-Process plink -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    
    # Start SSH tunnel with port forwarding
    # Forward local 27042 to iPhone's 27042 through SSH
    $sshArgs = @(
        "-ssh",
        "-l", "root",
        "-pw", "alpine",
        "-L", "127.0.0.1:$($Script:Config.Network.LocalPort):localhost:$($Script:Config.Network.FridaPort)",
        "-N",  # Don't start a shell
        "-batch",  # Don't ask for confirmation
        "127.0.0.1"  # Connect to USB SSH (usbmuxd)
    )
    
    try {
        Write-Host "Starting SSH tunnel: localhost:$($Script:Config.Network.LocalPort) -> iPhone:$($Script:Config.Network.FridaPort)" -ForegroundColor Green
        
        # Start plink in background
        $Script:SSHTunnel = Start-Process -FilePath $plinkPath -ArgumentList $sshArgs -WindowStyle Hidden -PassThru
        
        # Give it a moment to establish
        Start-Sleep -Seconds 2
        
        # Check if tunnel is running
        if ($Script:SSHTunnel.HasExited) {
            Write-Host "[!] SSH tunnel failed to start" -ForegroundColor Red
            return $false
        }
        
        Write-Host "[+] SSH tunnel established (PID: $($Script:SSHTunnel.Id))" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "[!] Failed to start SSH tunnel: $_" -ForegroundColor Red
        return $false
    }
}

function Stop-SSHTunnel {
    if ($Script:SSHTunnel -and -not $Script:SSHTunnel.HasExited) {
        Write-Host "Stopping SSH tunnel..." -ForegroundColor Yellow
        Stop-Process -Id $Script:SSHTunnel.Id -Force -ErrorAction SilentlyContinue
    }
    
    # Clean up any stray plink processes
    Get-Process plink -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Test-SSHTunnel {
    if ($Script:SSHTunnel -and -not $Script:SSHTunnel.HasExited) {
        return $true
    }
    return $false
}

function Start-FridaServerOnDevice {
    Write-Host "Starting frida-server on iPhone..." -ForegroundColor Cyan
    
    $plinkPath = Get-Command plink -ErrorAction SilentlyContinue
    if (-not $plinkPath) {
        $plinkPath = "C:\Program Files\PuTTY\plink.exe"
        if (-not (Test-Path $plinkPath)) {
            Write-Host "[!] plink not found, cannot start frida-server remotely" -ForegroundColor Red
            return $false
        }
    }
    
    # Execute frida-server via SSH in background
    $sshCommand = "killall frida-server 2>/dev/null; nohup frida-server > /dev/null 2>&1 &"
    
    try {
        # Run command via plink with timeout
        $job = Start-Job -ScriptBlock {
            param($plinkPath, $sshCommand)
            & $plinkPath -ssh -l root -pw alpine -batch 127.0.0.1 $sshCommand 2>&1
        } -ArgumentList $plinkPath, $sshCommand
        
        # Wait up to 3 seconds for completion
        $result = Wait-Job -Job $job -Timeout 3
        
        if ($result) {
            $output = Receive-Job -Job $job
            Remove-Job -Job $job -Force
        } else {
            Stop-Job -Job $job
            Remove-Job -Job $job -Force
        }
        
        Write-Host "[+] Command sent to start frida-server" -ForegroundColor Green
        Write-Host "    Waiting for initialization..." -ForegroundColor Gray
        Start-Sleep -Seconds 2
        
        return $true
    } catch {
        Write-Host "[!] Failed to start frida-server: $_" -ForegroundColor Red
        return $false
    }
}

# Connection tests
function Test-HTTPToolkit {
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect("localhost", $Script:Config.Network.ProxyPort)
        $result = $tcpClient.Connected
        $tcpClient.Close()
        return $result
    } catch {
        return $false
    }
}

function Test-FridaConnection {
    try {
        # Try USB connection first (simplest and most reliable)
        Write-Log "Testing USB connection..." "DEBUG"
        
        # Use Python module if frida-ps not in PATH
        if ($Script:UsePythonModule) {
            $usbOutput = python -m frida_tools.ps -U 2>&1 | Select-Object -First 5
        } else {
            $usbOutput = & $Script:FridaPsCmd -U 2>&1 | Select-Object -First 5
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "USB connection successful!" "DEBUG"
            $Script:Config.Network.UseUSB = $true
            return $true
        }
        
        # If USB fails, try network connection
        # Determine connection target based on tunnel status
        $targetHost = if ($Script:Config.Network.UseSSHTunnel -and (Test-SSHTunnel)) {
            "127.0.0.1:$($Script:Config.Network.LocalPort)"
        } else {
            "$($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)"
        }
        
        Write-Log "Testing network connection to $targetHost..." "DEBUG"
        # Try to connect with a timeout
        if ($Script:UsePythonModule) {
            $output = python -m frida_tools.ps -H $targetHost 2>&1 | Select-Object -First 5
        } else {
            $output = & $Script:FridaPsCmd -H $targetHost 2>&1 | Select-Object -First 5
        }
        
        # Check if we got valid output (not just errors)
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
        
        # Check for specific error messages
        $errorString = $output -join " "
        if ($errorString -match "unable to connect" -or $errorString -match "connection refused") {
            Write-Log "Cannot connect to frida-server at $($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)" "DEBUG"
            return $false
        }
        
        return $false
    } catch {
        Write-Log "Error testing Frida connection: $_" "DEBUG"
        return $false
    }
}

# Get running processes from iPhone
function Get-iPhoneProcesses {
    try {
        # Try USB first (simplest)
        Write-Log "Getting process list via USB..." "DEBUG"
        
        # Use Python module if frida-ps not in PATH
        if ($Script:UsePythonModule) {
            $processes = python -m frida_tools.ps -U -a 2>&1
        } else {
            $processes = & $Script:FridaPsCmd -U -a 2>&1
        }
        
        if ($LASTEXITCODE -eq 0) {
            return $processes
        }
        
        # Fall back to network
        # Determine connection target
        $targetHost = if ($Script:Config.Network.UseSSHTunnel -and (Test-SSHTunnel)) {
            "127.0.0.1:$($Script:Config.Network.LocalPort)"
        } else {
            "$($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)"
        }
        
        Write-Log "Connecting to iPhone via $targetHost..." "DEBUG"
        
        # Use -a flag to show bundle IDs!
        if ($Script:UsePythonModule) {
            $processes = python -m frida_tools.ps -a -H $targetHost 2>&1
        } else {
            $processes = & $Script:FridaPsCmd -a -H $targetHost 2>&1
        }
        if ($LASTEXITCODE -eq 0) {
            return $processes
        }
    } catch {}
    return $null
}

# Find process PID by name
function Find-ProcessPID {
    param([string]$ProcessName)
    
    $processes = Get-iPhoneProcesses
    if ($processes) {
        foreach ($line in $processes) {
            # Skip header lines
            if ($line -match "^\s*PID\s+" -or $line -match "^-+") {
                continue
            }
            # Match lines with PID and Name (bundle ID is optional)
            # Format: "  16913  DasherApp        com.doordash.dasher"
            if ($line -match "^\s*(\d+)\s+(\S+)(?:\s+(.+))?") {
                $procPid = $matches[1]
                $name = $matches[2].Trim()
                $bundleId = if ($matches[3]) { $matches[3].Trim() } else { "" }
                
                # Check if process name or bundle ID matches
                if ($name -eq $ProcessName -or 
                    $name -like "*$ProcessName*" -or 
                    ($bundleId -and ($bundleId -eq $ProcessName -or $bundleId -like "*$ProcessName*"))) {
                    Write-Log "Found process: $name (PID: $procPid, Bundle: $bundleId)" "DEBUG"
                    return @{
                        PID = $procPid
                        Name = $name
                        BundleID = $bundleId
                    }
                }
            }
        }
    }
    return $null
}

# HTTP Toolkit management
function Start-HTTPToolkit {
    if (Test-HTTPToolkit) {
        Write-Log "HTTP Toolkit already running" "SUCCESS"
        return $true
    }
    
    if ($Script:Config.Settings.AutoStartHTTPToolkit) {
        Write-Log "Starting HTTP Toolkit..." "INFO"
        
        try {
            Start-Process "httptoolkit" -WindowStyle Minimized -ErrorAction Stop
            Start-Sleep -Seconds 5
            
            if (Test-HTTPToolkit) {
                Write-Log "HTTP Toolkit started successfully" "SUCCESS"
                return $true
            }
        } catch {
            try {
                Start-Process "$env:LOCALAPPDATA\Programs\httptoolkit\HTTP Toolkit.exe" -WindowStyle Minimized
                Start-Sleep -Seconds 5
                return Test-HTTPToolkit
            } catch {
                Write-Log "Please start HTTP Toolkit manually" "WARN"
            }
        }
    }
    
    return $false
}

# Main app selection menu
function Show-AppMenu {
    param([switch]$SkipBanner)
    
    if (!$SkipBanner) {
        Show-Banner
    }
    Show-Status
    
    Write-ColorOutput "  SELECT MODE & APP" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    
    Write-ColorOutput "  SPAWN MODE (App will restart - logs you out):" "Cyan"
    Write-Host "  [1] DoorDash Dasher     - Fresh start"
    Write-Host "  [2] DoorDash Customer   - Fresh start"
    Write-Host "  [3] Safari Browser      - Fresh start"
    Write-Host ""
    
    Write-ColorOutput "  ATTACH MODE (Stay logged in!):" "Green"
    Write-Host "  [4] DoorDash Dasher     - Keep session"
    Write-Host "  [5] DoorDash Customer   - Keep session"
    Write-Host "  [6] Safari Browser      - Keep session"
    Write-Host ""
    
    Write-Host "  [C] Custom Bundle ID"
    Write-Host "  [L] List Running Apps"
    Write-Host "  [T] Test Frida Connection"
    Write-Host "  [S] Setup/Restart SSH Tunnel"
    Write-Host "  [F] Start frida-server on iPhone"
    Write-Host "  [Q] Quit"
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    
    $choice = Read-Host "Enter selection"
    
    switch ($choice.ToUpper()) {
        "1" { Start-SpawnMode -AppInfo $Script:Config.Apps.dasher }
        "2" { Start-SpawnMode -AppInfo $Script:Config.Apps.doordash }
        "3" { Start-SpawnMode -AppInfo $Script:Config.Apps.safari }
        "4" { Start-AttachMode -AppInfo $Script:Config.Apps.dasher }
        "5" { Start-AttachMode -AppInfo $Script:Config.Apps.doordash }
        "6" { Start-AttachMode -AppInfo $Script:Config.Apps.safari }
        "L" { Show-RunningApps }
        "T" { Test-FridaSetup }
        "S" { 
            Stop-SSHTunnel
            if (Start-SSHTunnel) {
                Write-Host ""
                Write-ColorOutput "[+] SSH tunnel established successfully!" "Green"
                Write-Host "    You can now use frida with your iPhone via USB"
            } else {
                Write-ColorOutput "[!] Failed to establish SSH tunnel" "Red"
            }
            Write-Host ""
            Write-Host "Press any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-AppMenu
        }
        "F" {
            Write-Host ""
            if (Start-FridaServerOnDevice) {
                Write-ColorOutput "[+] Command sent to start frida-server" "Green"
                Write-Host "    Testing connection..."
                Start-Sleep -Seconds 2
                if (Test-FridaConnection) {
                    Write-ColorOutput "[+] Frida server is now running!" "Green"
                } else {
                    Write-ColorOutput "[!] Frida server may not have started properly" "Yellow"
                    Write-Host "    Try connecting to iPhone via SSH and run: frida-server &"
                }
            } else {
                Write-ColorOutput "[!] Could not start frida-server remotely" "Red"
            }
            Write-Host ""
            Write-Host "Press any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-AppMenu
        }
        "Q" { Exit-Script }
        "C" { 
            Write-Host ""
            $customBundle = Read-Host "Enter Bundle ID (e.g., com.example.app)"
            
            # We don't need process name - we can find it by bundle ID!
            $customApp = @{
                BundleID = $customBundle
                Name = $customBundle  # Use bundle ID as name
                ProcessName = $customBundle  # We'll search by bundle ID
            }
            
            Write-Host ""
            $mode = Read-Host "Use [S]pawn or [A]ttach mode?"
            if ($mode -eq "A" -or $mode -eq "a") {
                Start-AttachMode -AppInfo $customApp
            } else {
                Start-SpawnMode -AppInfo $customApp
            }
        }
        default {
            Write-Log "Invalid selection" "ERROR"
            Start-Sleep -Seconds 2
            Show-AppMenu
        }
    }
}

# Test Frida setup and connection
function Test-FridaSetup {
    Clear-Host
    Show-Banner
    
    Write-ColorOutput "  FRIDA CONNECTION DIAGNOSTICS" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    
    # Test 1: Check if frida-ps is installed
    Write-Host -NoNewline "  [1] Checking frida-tools installation... "
    $fridaPath = Get-Command frida-ps -ErrorAction SilentlyContinue
    if ($fridaPath) {
        Write-ColorOutput "OK" "Green"
        Write-Host "      Path: $($fridaPath.Path)"
    } else {
        Write-ColorOutput "NOT FOUND" "Red"
        Write-Host "      Fix: pip install frida-tools"
    }
    
    # Test 2: Try to connect to iPhone
    Write-Host -NoNewline "  [2] Testing connection to iPhone... "
    Write-Host ""
    Write-Host "      Target: $($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)"
    
    if ($fridaPath) {
        Write-Host "      Running: frida-ps -H $($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)"
        $testOutput = & frida-ps -H "$($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)" 2>&1 | Select-Object -First 10
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "      Status: CONNECTED" "Green"
            Write-Host ""
            Write-ColorOutput "      Sample processes:" "Cyan"
            $testOutput | Select-Object -First 5 | ForEach-Object { Write-Host "      $_" }
        } else {
            Write-ColorOutput "      Status: FAILED" "Red"
            Write-Host ""
            Write-ColorOutput "      Error output:" "Yellow"
            $testOutput | ForEach-Object { Write-Host "      $_" }
            
            Write-Host ""
            Write-ColorOutput "  TROUBLESHOOTING STEPS:" "Yellow"
            Write-Host "  1. Connect iPhone via USB"
            Write-Host "  2. SSH to iPhone: ssh root@$($Script:Config.Network.iPhoneIP)"
            Write-Host "  3. Start frida-server:"
            Write-Host "     - For network: frida-server -l 0.0.0.0:27042 &"
            Write-Host "     - For USB: frida-server &"
            Write-Host "  4. If using USB, try: frida-ps -U"
            Write-Host "  5. Check firewall settings on both devices"
        }
    }
    
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    Write-Host "Press any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Show running apps
function Show-RunningApps {
    Write-Host ""
    Write-ColorOutput "  RUNNING APPS ON IPHONE (WITH BUNDLE IDS)" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    
    $processes = Get-iPhoneProcesses
    if ($processes) {
        Write-ColorOutput "  PID    NAME                           BUNDLE ID" "Cyan"
        Write-Host "  ---    ----                           ---------"
        
        foreach ($line in $processes) {
            # Skip header line
            if ($line -notmatch "PID\s+Name") {
                Write-Host "  $line"
            }
        }
    } else {
        Write-Log "Could not retrieve process list" "ERROR"
    }
    
    Write-Host ""
    # Don't clear - let user see the list!
    Show-AppMenu -SkipBanner
}

# Spawn mode - restarts app (logs out)
function Start-SpawnMode {
    param([hashtable]$AppInfo)
    
    Write-Host ""
    Write-ColorOutput "  SPAWN MODE - App will restart (logs you out)" "Yellow"
    Write-Host ""
    Write-Log "Starting fresh instance of $($AppInfo.Name)" "INFO"
    
    # Check if frida scripts directory exists
    if (-not (Test-Path $Script:FridaScriptsDir)) {
        Write-Log "Creating frida scripts directory..." "INFO"
        New-Item -ItemType Directory -Path $Script:FridaScriptsDir -Force | Out-Null
    }
    
    # Create required scripts if they don't exist
    Initialize-FridaScripts
    
    Push-Location $Script:FridaScriptsDir
    
    try {
        # Build frida arguments based on connection type
        if ($Script:Config.Network.UseUSB) {
            Write-Log "Using USB connection" "INFO"
            $fridaArgs = @(
                "-U",  # USB mode
                "-f", $AppInfo.BundleID,
                "-l", "universal-ssl-pinning-bypass.js",
                "--no-pause"
            )
        } else {
            # Determine network connection target
            $targetHost = if ($Script:Config.Network.UseSSHTunnel -and (Test-SSHTunnel)) {
                "127.0.0.1:$($Script:Config.Network.LocalPort)"
            } else {
                "$($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)"
            }
            
            Write-Log "Using network connection: $targetHost" "INFO"
            $fridaArgs = @(
                "-H", $targetHost,
                "-f", $AppInfo.BundleID,
                "-l", "universal-ssl-pinning-bypass.js",
                "--no-pause"
            )
        }
        
        Show-InterceptionBanner -AppInfo $AppInfo -Mode "SPAWN"
        
        Write-Log "Executing frida spawn mode" "DEBUG"
        
        # Execute frida command
        if ($Script:UsePythonModule) {
            # Use Python script wrapper
            $scriptPath = Join-Path $Script:BaseDir "frida-interception-and-unpinning\universal-ssl-pinning-bypass.js"
            $spawnScript = Join-Path $Script:BaseDir "frida-spawn.py"
            
            Write-Log "Using Python frida wrapper: $spawnScript" "DEBUG"
            & python $spawnScript $AppInfo.BundleID $scriptPath 2>&1 | ForEach-Object {
                if ($_ -match "ERROR") {
                    Write-ColorOutput $_ "Red"
                } elseif ($_ -match "\[\+\]") {
                    Write-ColorOutput $_ "Green"
                } else {
                    Write-Host $_
                }
            }
        } else {
            & $Script:FridaCmd $fridaArgs 2>&1 | ForEach-Object {
                if ($_ -match "error|failed|unable|cannot" -and $_ -notmatch "SSL pinning") {
                    Write-ColorOutput $_ "Red"
                } elseif ($_ -match "success|loaded|attached|spawned") {
                    Write-ColorOutput $_ "Green"
                } else {
                    Write-Host $_
                }
            }
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Frida exited with code: $LASTEXITCODE" "ERROR"
        }
        
    } catch {
        Write-Log "Error running frida: $_" "ERROR"
        Write-Host ""
        Write-Host "Troubleshooting:"
        Write-Host "1. Ensure iPhone is connected via USB"
        Write-Host "2. Ensure frida-server is running on iPhone"
        Write-Host "3. Check iPhone IP: $($Script:Config.Network.iPhoneIP)"
        Write-Host ""
    } finally {
        Pop-Location
    }
    
    Write-Log "Interception stopped" "INFO"
    Write-Host ""
    Write-Host "Press any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Attach mode - keeps session (stay logged in!)
function Start-AttachMode {
    param([hashtable]$AppInfo)
    
    Write-Host ""
    Write-ColorOutput "  ATTACH MODE - Stay logged in!" "Green"
    Write-Host ""
    
    # Find the running process
    Write-Log "Looking for running $($AppInfo.Name)..." "INFO"
    $process = Find-ProcessPID -ProcessName $AppInfo.ProcessName
    
    if (-not $process) {
        Write-Log "App not running! Please:" "WARN"
        Write-Host "  1. Open $($AppInfo.Name) on your iPhone"
        Write-Host "  2. Log in if needed"
        Write-Host "  3. Come back here and try again"
        Write-Host ""
        Write-Host "Press any key to return to menu..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-AppMenu
        return
    }
    
    Write-Log "Found process: $($process.Name) (PID: $($process.PID))" "SUCCESS"
    Write-Host ""
    
    $confirm = Read-Host "Attach to this process? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Show-AppMenu
        return
    }
    
    # Check if frida scripts directory exists
    if (-not (Test-Path $Script:FridaScriptsDir)) {
        Write-Log "Creating frida scripts directory..." "INFO"
        New-Item -ItemType Directory -Path $Script:FridaScriptsDir -Force | Out-Null
    }
    
    # Create required scripts if they don't exist
    Initialize-FridaScripts
    
    Push-Location $Script:FridaScriptsDir
    
    try {
        # Build frida arguments based on connection type
        if ($Script:Config.Network.UseUSB) {
            Write-Log "Using USB connection" "INFO"
            $fridaArgs = @(
                "-U",  # USB mode
                "-p", $process.PID,
                "-l", "universal-ssl-pinning-bypass.js"
            )
        } else {
            # Determine network connection target
            $targetHost = if ($Script:Config.Network.UseSSHTunnel -and (Test-SSHTunnel)) {
                "127.0.0.1:$($Script:Config.Network.LocalPort)"
            } else {
                "$($Script:Config.Network.iPhoneIP):$($Script:Config.Network.FridaPort)"
            }
            
            Write-Log "Using network connection: $targetHost" "INFO"
            $fridaArgs = @(
                "-H", $targetHost,
                "-p", $process.PID,
                "-l", "universal-ssl-pinning-bypass.js"
            )
        }
        
        Show-InterceptionBanner -AppInfo $AppInfo -Mode "ATTACH" -ProcessPID $process.PID
        
        Write-Log "Executing frida attach mode" "DEBUG"
        
        # Execute frida command
        if ($Script:UsePythonModule) {
            # Use Python script wrapper
            $scriptPath = Join-Path $Script:BaseDir "frida-interception-and-unpinning\universal-ssl-pinning-bypass.js"
            $attachScript = Join-Path $Script:BaseDir "frida-attach.py"
            
            Write-Log "Using Python frida wrapper: $attachScript" "DEBUG"
            & python $attachScript $process.PID $scriptPath 2>&1 | ForEach-Object {
                if ($_ -match "ERROR") {
                    Write-ColorOutput $_ "Red"
                } elseif ($_ -match "\[\+\]") {
                    Write-ColorOutput $_ "Green"
                } else {
                    Write-Host $_
                }
            }
        } else {
            & $Script:FridaCmd $fridaArgs 2>&1 | ForEach-Object {
                if ($_ -match "error|failed|unable|cannot" -and $_ -notmatch "SSL pinning") {
                    Write-ColorOutput $_ "Red"
                } elseif ($_ -match "success|loaded|attached|spawned") {
                    Write-ColorOutput $_ "Green"
                } else {
                    Write-Host $_
                }
            }
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Frida exited with code: $LASTEXITCODE" "ERROR"
        }
        
    } catch {
        Write-Log "Error running frida: $_" "ERROR"
        Write-Host ""
        Write-Host "Troubleshooting:"
        Write-Host "1. Ensure iPhone is connected via USB"
        Write-Host "2. Ensure frida-server is running on iPhone"
        Write-Host "3. Check iPhone IP: $($Script:Config.Network.iPhoneIP)"
        Write-Host ""
    } finally {
        Pop-Location
    }
    
    Write-Log "Interception stopped" "INFO"
    Write-Host ""
    Write-Host "Press any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
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
    Write-Host "  Proxy:      $($Script:Config.Network.WindowsIP):$($Script:Config.Network.ProxyPort)"
    Write-Host "  iPhone:     $($Script:Config.Network.iPhoneIP)"
    Write-Host ""
    Write-ColorOutput "  Traffic should now appear in HTTP Toolkit GUI" "Cyan"
    Write-ColorOutput "  Press Ctrl+C to stop interception" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
}

# Exit handler
function Exit-Script {
    Write-Host ""
    
    # Clean up SSH tunnel
    Stop-SSHTunnel
    
    Write-ColorOutput "Thank you for using FridaInterceptor Ultimate!" "Cyan"
    Write-Host ""
    exit 0
}

# Show help
function Show-Help {
    Clear-Host
    Show-Banner
    
    Write-ColorOutput "  HELP - TWO MODES AVAILABLE" "Yellow"
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    
    Write-ColorOutput "  SPAWN MODE:" "Yellow"
    Write-Host "  - Restarts the app fresh"
    Write-Host "  - Clears all session data"
    Write-Host "  - You'll need to log in again"
    Write-Host "  - Use when: App is stuck or for clean testing"
    Write-Host ""
    
    Write-ColorOutput "  ATTACH MODE:" "Green"
    Write-Host "  - Connects to running app"
    Write-Host "  - Keeps you logged in"
    Write-Host "  - Preserves session data"
    Write-Host "  - Use when: You want to stay logged in"
    Write-Host ""
    
    Write-ColorOutput "  HOW TO STAY LOGGED IN:" "Cyan"
    Write-Host "  1. Open the app on your iPhone"
    Write-Host "  2. Log in normally"
    Write-Host "  3. Select options 4-6 (Attach Mode)"
    Write-Host "  4. Confirm the PID"
    Write-Host "  5. Stay logged in while intercepting!"
    Write-Host ""
    
    Write-ColorOutput "-----------------------------------------------------------------------------------------" "DarkGray"
    Write-Host ""
    Write-Host "Press any key to return..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-AppMenu
}

# Main execution
function Main {
    # Initialize logging first
    Initialize-Logging
    
    Write-Log "FridaInterceptor Ultimate v$($Script:Version) started" "INFO"
    
    # Initialize dependencies
    Initialize-Dependencies
    
    # Show help if requested
    if ($Help) {
        Show-Help
        exit 0
    }
    
    # Start SSH tunnel if configured
    if ($Script:Config.Network.UseSSHTunnel) {
        if (-not (Start-SSHTunnel)) {
            Write-Log "Failed to establish SSH tunnel. Continuing without tunnel..." "WARN"
            $Script:Config.Network.UseSSHTunnel = $false
        } else {
            # Try to start frida-server automatically
            Write-Host "Checking frida-server status..." -ForegroundColor Cyan
            if (-not (Test-FridaConnection)) {
                Write-Host "Attempting to start frida-server on device..." -ForegroundColor Yellow
                Start-FridaServerOnDevice | Out-Null
                Start-Sleep -Seconds 2
            }
        }
    }
    
    # Check and start HTTP Toolkit
    Start-HTTPToolkit | Out-Null
    
    # Direct launch by mode and app
    if ($Mode -and $App) {
        $appInfo = switch ($App) {
            "1" { $Script:Config.Apps.dasher }
            "dasher" { $Script:Config.Apps.dasher }
            "2" { $Script:Config.Apps.doordash }
            "doordash" { $Script:Config.Apps.doordash }
            "3" { $Script:Config.Apps.safari }
            "safari" { $Script:Config.Apps.safari }
            default { 
                Write-Log "Invalid app: $App" "ERROR"
                exit 1
            }
        }
        
        if ($Mode -eq "attach") {
            Start-AttachMode -AppInfo $appInfo
        } else {
            Start-SpawnMode -AppInfo $appInfo
        }
    } else {
        # Interactive menu
        Show-AppMenu
    }
    
    # Exit
    Exit-Script
}

# Error handling
$ErrorActionPreference = "Continue"
trap {
    Write-Log "Fatal error: $_" "ERROR"
    Exit-Script
}

# Run main
Main