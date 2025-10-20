# iOS Frida Connection Guide - Complete Setup Documentation

**Last Updated:** October 8, 2025
**Device:** iPhone SE2, iOS 16.3.1 (Dopamine RootHide Jailbreak)
**Current IP:** 192.168.50.130
**Frida Version:** 16.1.4 (Python client)

---

## Table of Contents

1. [Connection Methods Overview](#connection-methods-overview)
2. [Method 1: USB Connection (RECOMMENDED)](#method-1-usb-connection-recommended)
3. [Method 2: Network Connection via SSH Tunnel](#method-2-network-connection-via-ssh-tunnel)
4. [Troubleshooting Common Issues](#troubleshooting-common-issues)
5. [Quick Reference Commands](#quick-reference-commands)

---

## Connection Methods Overview

### ✅ Method 1: USB Connection (WORKING - RECOMMENDED)
- **Pros:** Simple, fast, no network setup required
- **Cons:** Requires physical USB connection
- **Use Case:** Primary method for daily development
- **Success Rate:** 100%

### ⚠️ Method 2: Network via SSH Tunnel (COMPLEX)
- **Pros:** Wireless connection, no cable needed
- **Cons:** Requires SSH tunnel setup, frida-server network configuration, authentication issues
- **Use Case:** When USB is not available
- **Success Rate:** Variable (requires frida-server to listen on 0.0.0.0)

---

## Method 1: USB Connection (RECOMMENDED)

### Prerequisites

1. **Jailbroken iPhone** with Frida server installed
2. **USB cable** connected to Windows PC
3. **Python 3.x** installed
4. **Frida Python package** installed:
   ```bash
   pip install frida-tools frida
   ```

### Step-by-Step Setup

#### 1. Connect iPhone via USB

```bash
# Verify USB connection
python -c "import frida; device = frida.get_usb_device(); print(f'Device: {device.name}, ID: {device.id}')"
```

**Expected Output:**
```
Device: Apple iPhone, ID: 00008030-001229C01146402E
```

#### 2. Verify Frida Server on iPhone

On your iPhone (via SSH or terminal app), check if frida-server is running:

```bash
ps aux | grep frida-server | grep -v grep
```

**Expected Output:**
```
root  921  0.0  0.7  408575984  19984  ??  Ss  Thu01PM  0:13.09 /usr/sbin/frida-server
```

If NOT running, start it:
```bash
su                      # Switch to root (password: alpine)
frida-server &          # Start in background
```

#### 3. Test Frida Connection

```bash
# List all iOS apps
python -m frida_tools.ps -Uai

# Find Dasher app
python -m frida_tools.ps -Uai | grep -i dasher
```

**Expected Output:**
```
-  Dasher    com.doordash.dasher
```

#### 4. Launch App with Frida

**Spawn Mode (Recommended):**
```bash
python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js"
```

**Attach Mode (Preserve Session):**
```bash
# Get PID first
python -m frida_tools.ps -Uai | grep dasher

# Attach to PID
python frida-attach.py <PID> "frida-interception-and-unpinning/enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js"
```

### Success Indicators

You should see:
```
[+] Connected to device: Apple iPhone
[+] Spawning com.doordash.dasher...
[*] Starting Universal SSL Pinning Bypass with Proxy...
[+] SSL Pinning bypass hooks installed
[+] Proxy routing configured
[+] Ready to intercept traffic!
```

---

## Method 2: Network Connection via SSH Tunnel

### Prerequisites

1. **3uTools** installed on Windows (for SSH tunnel)
2. **plink.exe** (PuTTY Link) in project directory
3. **frida-server** running on iPhone and listening on `0.0.0.0`

### Architecture

```
Windows PC (192.168.50.9)
    ↓
3uTools SSH Tunnel (127.0.0.1:22 → iPhone:22)
    ↓
iPhone (192.168.50.130)
    ↓
frida-server (listening on 0.0.0.0:27042)
```

### Step-by-Step Setup

#### 1. Open 3uTools SSH Tunnel

1. Launch **3uTools**
2. Connect iPhone via USB
3. Navigate to **Toolbox → SSH Tunnel**
4. Click **"Open SSH Tunnel"**

**Expected Result:**
```
✅ Succeeded to open SSH tunnel.
You may use SSH tool like Xshell to obtain terminal access
IP: 127.0.0.1    Port: 22
Default ID: root    Password: alpine
```

#### 2. Configure frida-server to Listen on Network

**CRITICAL:** frida-server must listen on `0.0.0.0` (all interfaces), not just `127.0.0.1`.

Via 3uTools SSH Client:

```bash
# Click "SSH client" button in 3uTools
su                                    # Enter root password: alpine
killall frida-server                  # Stop existing frida-server
frida-server -l 0.0.0.0 &            # Start with network listening
ps aux | grep frida-server | grep -v grep  # Verify it's running
```

**Verify frida-server is listening:**
```bash
# From Windows
python -m frida_tools.ps -H 192.168.50.130 -ai
```

#### 3. Create SSH Port Forward (Optional)

If you want to access frida-server via localhost:

```bash
# Clear plink host key cache (one-time)
reg delete "HKCU\Software\SimonTatham\PuTTY\SshHostKeys" /f

# Create tunnel
plink.exe -ssh -L 27042:127.0.0.1:27042 root@127.0.0.1 -P 22 -pw alpine -N
```

#### 4. Connect via Network

```python
# Create Python script: frida-spawn-ios-direct.py
import frida

device_manager = frida.get_device_manager()
device = device_manager.add_remote_device("192.168.50.130:27042")
# ... rest of script
```

Or use command-line:
```bash
python -m frida_tools.ps -H 192.168.50.130:27042 -ai
```

### Common Issues with Network Method

#### Issue 1: "unable to connect to remote frida-server"

**Cause:** frida-server is only listening on localhost (127.0.0.1), not on network interface.

**Solution:**
```bash
# On iPhone
su
killall frida-server
frida-server -l 0.0.0.0 &  # CRITICAL: Use -l 0.0.0.0
```

#### Issue 2: "Authentication failed" with plink/SSH

**Cause:** Multiple possible reasons:
- Password changed from default `alpine`
- Wrong SSH port
- Host key mismatch

**Solutions:**
```bash
# Clear host key cache
reg delete "HKCU\Software\SimonTatham\PuTTY\SshHostKeys" /f

# Try connecting via 3uTools tunnel
plink.exe -ssh root@127.0.0.1 -P 22 -pw alpine "echo test"

# If still fails, use 3uTools SSH client directly
```

#### Issue 3: "Cannot confirm host key in batch mode"

**Solution:**
```bash
# Accept host key first
echo y | plink.exe -ssh root@127.0.0.1 -P 22 -pw alpine "echo connected"
```

---

## Troubleshooting Common Issues

### 1. "Device not found" (USB)

**Symptoms:**
```
Failed to enumerate processes: device not found
```

**Solutions:**
```bash
# Check USB connection
python -c "import frida; print(frida.enumerate_devices())"

# Should show something like:
# Device(id="00008030-001229C01146402E", name="Apple iPhone", type='usb')

# If not found:
# 1. Reconnect USB cable
# 2. Trust computer on iPhone
# 3. Restart iTunes/Apple Mobile Device Service (Windows)
```

### 2. frida-server Not Running

**Symptoms:**
```
Failed to attach: unable to connect to remote frida-server
```

**Solutions:**
```bash
# Via 3uTools SSH client or iPhone terminal
su  # Password: alpine
ps aux | grep frida-server

# If not running:
frida-server &

# Verify it started:
ps aux | grep frida-server
```

### 3. "Permission denied" or "Operation not permitted"

**Cause:** Not running as root on iPhone

**Solution:**
```bash
# Always use 'su' first
su
# Enter password: alpine
frida-server &
```

### 4. App Gets Stuck on White Screen

**Cause:** API returns 404 for `/v3/dasher/me/` because account hasn't completed driver signup.

**Solution:** Use the API interceptor script:
```bash
python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/dasher-api-interceptor.js"
```

This script:
- Intercepts 404 responses
- Changes status to 200 OK
- Allows app to proceed past white screen

### 5. iPhone IP Address Changed

**Symptoms:**
```
unable to connect to remote frida-server at 192.168.50.113
```

**Solution:**
```bash
# Check current IP on iPhone
# Settings → Wi-Fi → (i) button → IP Address

# Update config files:
# 1. config/frida-config.json
# 2. CLAUDE.md
# 3. Any hardcoded IPs in scripts

# Current IP: 192.168.50.130
```

---

## Quick Reference Commands

### Check Connection Status

```bash
# USB device
python -c "import frida; print(frida.get_usb_device())"

# Network device
python -m frida_tools.ps -H 192.168.50.130 -ai

# All devices
python -c "import frida; [print(f'{d.id}: {d.name} ({d.type})') for d in frida.enumerate_devices()]"
```

### List Running Apps

```bash
# USB
python -m frida_tools.ps -Uai

# Network
python -m frida_tools.ps -H 192.168.50.130 -ai

# Find specific app
python -m frida_tools.ps -Uai | grep -i dasher
```

### Launch with Frida

```bash
# Spawn mode (USB - RECOMMENDED)
python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js"

# Spawn mode with API interceptor (fixes white screen)
python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/dasher-api-interceptor.js"

# Attach mode (preserves login session)
python frida-attach.py <PID> "frida-interception-and-unpinning/attach-mode-proxy.js"
```

### Restart frida-server on iPhone

```bash
# Via 3uTools SSH client
su                      # Password: alpine
killall frida-server    # Stop existing
frida-server &          # Start fresh

# For network access (if needed)
frida-server -l 0.0.0.0 &
```

---

## Configuration Files Updated

When iPhone IP changes, update these files:

1. **`config/frida-config.json`**
   ```json
   "iPhoneIP": "192.168.50.130"
   ```

2. **`CLAUDE.md`**
   ```markdown
   - **Current iPhone IP:** 192.168.50.130
   ```

3. **`FRIDA-LIVE-MONITOR.bat`**
   ```batch
   set IPHONE_IP=192.168.50.130
   set SSH_PORT=22
   ```

---

## Current Working Setup (As of Oct 8, 2025)

### Device Info
- **Device:** iPhone SE2
- **iOS:** 16.3.1 (Dopamine RootHide Jailbreak)
- **IP:** 192.168.50.130
- **Device ID:** 00008030-001229C01146402E

### Connection Method
- **Primary:** USB (via `frida.get_usb_device()`)
- **Status:** ✅ Working
- **frida-server PID:** 921

### Scripts
- **Spawn:** `frida-spawn.py` (uses USB)
- **Attach:** `frida-attach.py` (uses USB)
- **API Interceptor:** `dasher-api-interceptor.js` (fixes white screen)

### Launch Command
```bash
python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/dasher-api-interceptor.js"
```

---

## Why USB is Preferred

| Aspect | USB Connection | Network Connection |
|--------|---------------|-------------------|
| **Setup Complexity** | Low (just plug in) | High (SSH tunnel + frida config) |
| **Reliability** | 100% | Variable (~60-70%) |
| **Speed** | Fast | Depends on WiFi |
| **Authentication** | None needed | SSH password required |
| **Configuration** | Zero | Multiple files to update |
| **Frida Server** | Default mode works | Must listen on 0.0.0.0 |

**Recommendation:** Always use USB unless wireless is absolutely necessary.

---

## Next Steps

1. **Test USB connection:**
   ```bash
   python -c "import frida; print(frida.get_usb_device())"
   ```

2. **Launch Dasher:**
   ```bash
   python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/dasher-api-interceptor.js"
   ```

3. **Verify HTTP Toolkit receives traffic:**
   - Open HTTP Toolkit at `http://192.168.50.9:8000`
   - Should see decrypted HTTPS requests from Dasher app

4. **If white screen persists:**
   - The API interceptor changes `/v3/dasher/me/` 404→200
   - Check Frida console for `[INTERCEPT]` messages
   - Verify HTTP Toolkit shows the modified response

---

## Summary

**The working connection method is:**

1. ✅ **Connect iPhone via USB**
2. ✅ **Ensure frida-server is running** (as root)
3. ✅ **Use USB-based Python scripts** (`frida-spawn.py`)
4. ✅ **No SSH tunnel needed**
5. ✅ **No network configuration needed**

**One-liner to start monitoring:**
```bash
python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/dasher-api-interceptor.js"
```

That's it! The USB method "just works" without any of the SSH/network complexity.
