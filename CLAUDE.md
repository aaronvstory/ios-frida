# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Frida Live Development Framework - A comprehensive mobile app interception toolkit for security research and network traffic analysis. Supports both iOS (via SSH tunnel) and Android (via USB/ADB) with live script development capabilities.

**Primary Use Case:** Bypass HTTP Toolkit proxy detection issues by injecting Frida scripts directly into mobile apps, enabling real-time HTTPS traffic inspection, SSL pinning bypass, and network manipulation.

## Dual Platform Architecture

### Android (Primary - Pixel 4)
- **Connection:** Direct USB via Frida/ADB
- **Device ID:** `1AEAFS000010KE`
- **Target Apps:**
  - `com.doordash.driverapp` (Dasher - Driver app)
  - `com.dd.doordash` (DoorDash - Customer app)
- **Key Feature:** Live interactive REPL for script development

### iOS (Legacy)
- **Connection:** SSH tunnel via 3uTools (127.0.0.1:22 → iPhone:22)
- **Target Device:** iPhone SE2, iOS 16.3.1 (Dopamine RootHide jailbreak)
- **Current iPhone IP:** 192.168.50.130
- **Default credentials:** root/alpine
- **Target Apps:** `com.doordash.dasher` (Dasher - Driver app only)
- **Note:** 3uTools SSH tunnel must be manually opened before Frida operations

## Core Components

### Python Scripts (Platform-Independent Core)
- **`frida-spawn.py`**: Spawn app fresh with Frida (app restarts, clean state)
  - Usage: `python frida-spawn.py <bundle_id> <script.js>`
  - Best for: Initial testing, reliable proxy routing

- **`frida-attach.py`**: Attach to running app (preserves session/login)
  - Usage: `python frida-attach.py <pid> <script.js>`
  - Best for: Session preservation, testing on logged-in state

- **`live-frida-repl.py`**: Interactive REPL environment (NEW - Android primary)
  - Usage: `python live-frida-repl.py <app_id> [--spawn]`
  - Features: Hot-reload, built-in templates, save/load scripts
  - **This is the recommended tool for development**

### JavaScript Injection Scripts (frida-interception-and-unpinning/)

**Android Templates (Java-based):**
- Built-in to `live-frida-repl.py` (basic, network, ssl-unpin, proxy, all)
- Hook OkHttp3, HttpURLConnection
- SSL unpinning via SSLContext, TrustManager, CertificatePinner

**iOS Templates (Objective-C-based):**
- `enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js` - Preferred (error-free)
- `attach-mode-proxy.js` - Optimized for running apps
- `universal-ssl-pinning-bypass-with-proxy.js` - Standard version
- Hook NSURLSession, SecTrustEvaluate methods

### Configuration
- **`config/frida-config.json`**: Network settings, app identifiers
  - `WindowsIP`: 192.168.50.9 (HTTP Toolkit host)
  - `ProxyPort`: 8000
  - `iPhoneIP`: 192.168.50.113

## Critical Commands

### Android Development (Recommended Workflow)

```bash
# Quick start - attach to running app
DASHER-LIVE-MONITOR.bat
# OR
python live-frida-repl.py com.doordash.driverapp

# Spawn app fresh with monitoring
DASHER-SPAWN-MONITOR.bat
# OR
python live-frida-repl.py com.doordash.driverapp --spawn

# Inside REPL:
frida> load all          # Complete monitoring + SSL bypass + proxy
frida> load network      # Network monitoring only
frida> load ssl-unpin    # SSL unpinning only
frida> load proxy        # Proxy configuration only
frida> js <code>         # Execute JavaScript in app context
frida> save script.js    # Save current script
frida> run script.js     # Load and execute script file
frida> quit              # Exit
```

### iOS Development (Legacy Workflow)

```bash
# Ensure 3uTools SSH tunnel is open first
# Then use iOS-focused launcher
FRIDA-LIVE-MONITOR.bat

# Or direct Python calls
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning/enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js
python frida-attach.py <PID> frida-interception-and-unpinning/attach-mode-proxy.js
```

### Verification & Testing

```bash
# Test setup
QUICK-TEST.bat

# List running apps
python -m frida_tools.ps -Uai

# Find specific app
python -m frida_tools.ps -Uai | grep -i dasher

# Get device info
python -c "import frida; device = frida.get_usb_device(); print(f'Device: {device.name}, ID: {device.id}')"
```

## Script Development Workflow

### Recommended: Live REPL Method

1. **Start REPL:**
   ```bash
   python live-frida-repl.py com.doordash.driverapp
   ```

2. **Load template and test:**
   ```
   frida> load all
   # Use app, observe output
   ```

3. **Save working version:**
   ```
   frida> save my-dasher-monitor.js
   ```

4. **Edit externally:**
   ```bash
   notepad my-dasher-monitor.js
   # Make changes
   ```

5. **Reload and test:**
   ```
   frida> run my-dasher-monitor.js
   # Iterate until satisfied
   ```

### Alternative: File-Based Method

1. Edit script file directly
2. Test with spawn/attach: `python frida-spawn.py <app> <script.js>`
3. Repeat until working

## Mode Selection Strategy

### Spawn Mode
- **When:** Initial testing, need reliable proxy routing, clean state OK
- **Behavior:** App restarts (user logged out), all traffic captured from start
- **Success Rate:** 100% for proxy routing
- **Trade-off:** Loses session state

### Attach Mode
- **When:** Must preserve login/session, testing logged-in features
- **Behavior:** Hooks into running app, may need refresh to activate
- **Success Rate:** Variable, depends on app's network initialization
- **Trade-off:** May miss early network calls

## HTTP Toolkit Integration

**Target:** `http://192.168.50.9:8000`

### Complete Workflow
1. Open HTTP Toolkit at target address
2. Launch Frida with proxy script (`load all` in REPL)
3. Verify success messages:
   - Android: `[+] Proxy configured: 192.168.50.9:8000`
   - iOS: `[+] Proxy configured: 192.168.50.9:8000`
4. Use target app to make requests
5. Traffic appears decrypted in HTTP Toolkit

### Common Issues
- **No traffic:** Use spawn mode instead of attach, or force refresh in app
- **SSL errors:** Ensure SSL bypass script loaded (`[+] SSLContext bypassed` on Android)
- **Connection refused:** Verify HTTP Toolkit is listening on correct IP:port

## JavaScript Hook Patterns

### Android (Java.perform)
```javascript
Java.perform(function() {
    var ClassName = Java.use('package.ClassName');
    ClassName.methodName.implementation = function(arg) {
        console.log('[HOOK] Called with: ' + arg);
        return this.methodName(arg); // Call original
    };
});
```

### iOS (ObjC.available)
```javascript
if (ObjC.available) {
    var ClassName = ObjC.classes.ClassName;
    Interceptor.attach(ClassName['- methodName:'].implementation, {
        onEnter: function(args) {
            console.log('[HOOK] Called');
        }
    });
}
```

## Built-in REPL Templates

| Template | Platform | Functionality |
|----------|----------|---------------|
| `basic` | Both | Minimal connection test |
| `network` | Android | OkHttp3 + HttpURLConnection request logging |
| `ssl-unpin` | Android | SSLContext, TrustManager, CertificatePinner bypass |
| `proxy` | Android | System proxy + OkHttp proxy configuration |
| `all` | Android | Complete: network monitoring + SSL bypass + proxy |

For iOS, use file-based scripts in `frida-interception-and-unpinning/`.

## Dependencies

Install via `requirements.txt`:
```bash
pip install -r requirements.txt
```

Required:
- frida-tools >= 12.0.0
- frida >= 16.0.0
- colorama >= 0.4.6

## Critical File Paths

- **Logs:** `logs/` - Debug output and monitoring logs
- **Config:** `config/frida-config.json` - Network and app settings
- **iOS Scripts:** `frida-interception-and-unpinning/*.js` - Pre-built injection scripts
- **Archive:** `archive/` - Old files (69 archived during cleanup)
- **Documentation:** See "Key Documentation Files" below

## Debugging Workflow

1. **Verify connection:**
   ```bash
   python -m frida_tools.ps -U
   ```
   Should list processes. If not, check USB/ADB connection.

2. **Check app availability:**
   ```bash
   python -m frida_tools.ps -Uai | grep -i <app_name>
   ```

3. **Test basic script:**
   ```bash
   python frida-spawn.py <app_id> test-script.js
   ```

4. **Check HTTP Toolkit:**
   - Verify listening on 192.168.50.9:8000
   - Look for console messages: `[+] Proxy configured`
   - Try spawn mode if attach mode fails

5. **Review logs:**
   - REPL shows real-time output
   - Check `logs/` for historical data

## Key Documentation Files

**Start Here:**
- `START-HERE-NEW.md` - Visual quick start for Android
- `FRIDA-CONNECTION-COMPLETE.md` - Connection success summary

**Complete Guides:**
- `docs/IOS-FRIDA-CONNECTION-GUIDE.md` - **COMPLETE iOS connection guide with USB & SSH methods**
- `LIVE-FRIDA-CONNECTION-GUIDE.md` - Full Android development guide (20KB)
- `LIVE-MANIPULATION-GUIDE.md` - iOS-focused network manipulation guide

**Project Info:**
- `WORKSPACE-CLEANUP-SUMMARY.md` - Project reorganization details
- `README.md` - Project overview

## Security & Ethical Use

**Authorized Use Only:**
- Security research on owned devices
- App debugging and development
- Network analysis and testing

**Not For:**
- Unauthorized access to systems
- Bypassing security for malicious purposes
- Production environment attacks without authorization

Default credentials (iOS): root/alpine - change on production devices.

## Platform-Specific Notes

### Android-Specific
- Uses Java reflection via `Java.use()`
- Most apps use OkHttp3 for networking
- SSL pinning often via CertificatePinner
- Proxy configuration via System properties or OkHttpClient builder

### iOS-Specific
- Uses Objective-C runtime via `ObjC.classes`
- Networking via NSURLSession (modern) or NSURLConnection (legacy)
- SSL pinning via SecTrustEvaluate or NSURLSession delegate methods
- Proxy configuration via NSURLSessionConfiguration
- Requires jailbroken device with Frida server installed

## Common Patterns

### Finding Class Names
```javascript
// Android
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes('keyword')) {
                console.log(className);
            }
        },
        onComplete: function() {}
    });
});

// iOS
for (var className in ObjC.classes) {
    if (className.includes('keyword')) {
        console.log(className);
    }
}
```

### Sending Data to Python
```javascript
send({type: 'request', url: url, method: method});
```

Python receives via `on_message` callback.
