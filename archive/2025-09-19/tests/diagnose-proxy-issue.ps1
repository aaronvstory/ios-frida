#!/usr/bin/env pwsh
# Quick diagnostic script for HTTP Toolkit proxy issues

Write-Host "`n=== FRIDA PROXY DIAGNOSTICS ===" -ForegroundColor Cyan

# Check if enhanced script exists
$enhancedScript = ".\frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy.js"
if (Test-Path $enhancedScript) {
    Write-Host "[✓] Enhanced proxy script found" -ForegroundColor Green
} else {
    Write-Host "[✗] Enhanced proxy script NOT found - this is likely the issue!" -ForegroundColor Red
    Write-Host "    Run: test-frida-interceptor.ps1 to validate setup" -ForegroundColor Yellow
}

# Check HTTP Toolkit connectivity
Write-Host "`n=== Testing HTTP Toolkit Proxy ===" -ForegroundColor Cyan
$proxyHost = "192.168.50.9"
$proxyPort = 8000

try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect($proxyHost, $proxyPort)
    if ($tcpClient.Connected) {
        Write-Host "[✓] HTTP Toolkit proxy is reachable at ${proxyHost}:${proxyPort}" -ForegroundColor Green
        $tcpClient.Close()
    }
} catch {
    Write-Host "[✗] Cannot connect to HTTP Toolkit at ${proxyHost}:${proxyPort}" -ForegroundColor Red
    Write-Host "    Ensure HTTP Toolkit is running and listening on port 8000" -ForegroundColor Yellow
}

# Check if frida is running
Write-Host "`n=== Checking Frida Processes ===" -ForegroundColor Cyan
$fridaProcesses = Get-Process | Where-Object { $_.ProcessName -like "*frida*" -or $_.CommandLine -like "*frida*" }
if ($fridaProcesses) {
    Write-Host "[✓] Frida processes found:" -ForegroundColor Green
    $fridaProcesses | ForEach-Object { Write-Host "    - $($_.ProcessName) (PID: $($_.Id))" }
} else {
    Write-Host "[!] No Frida processes detected locally" -ForegroundColor Yellow
}

# Test frida-ps command
Write-Host "`n=== Testing Frida Device Connection ===" -ForegroundColor Cyan
try {
    $result = & python -m frida_tools.ps -U 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[✓] Frida can connect to iOS device via USB" -ForegroundColor Green
    } else {
        Write-Host "[✗] Frida cannot connect to iOS device" -ForegroundColor Red
        Write-Host "    Error: $result" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[✗] Frida tools not available" -ForegroundColor Red
}

# Provide solution
Write-Host "`n=== RECOMMENDED SOLUTION ===" -ForegroundColor Cyan
Write-Host "1. Ensure HTTP Toolkit is running on port 8000" -ForegroundColor White
Write-Host "2. Run the script with option 5 (DoorDash Customer - Attach mode)" -ForegroundColor White
Write-Host "3. Watch for this output:" -ForegroundColor White
Write-Host "   [+] Using ENHANCED proxy script" -ForegroundColor Green
Write-Host "   [+] Features: Comprehensive network hooks..." -ForegroundColor Green
Write-Host "4. In the app, trigger a network request (refresh, navigate, etc.)" -ForegroundColor White
Write-Host "5. Check HTTP Toolkit for incoming traffic" -ForegroundColor White

Write-Host "`nIf still no traffic, try:" -ForegroundColor Yellow
Write-Host "- Force quit and restart the DoorDash app" -ForegroundColor White
Write-Host "- Use option 2 (Spawn mode) instead of Attach" -ForegroundColor White
Write-Host "- Check iOS WiFi proxy settings (should be empty/none)" -ForegroundColor White

Write-Host "`n"