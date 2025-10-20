# 🚀 Live Frida Connection & Script Development Guide

## 🎯 Connection Summary

**Device:** Pixel 4 (Android)
**Connection:** USB (Frida over ADB)
**Apps Available:**
- **Dasher** - `com.doordash.driverapp` (Driver app)
- **DoorDash** - `com.dd.doordash` (Customer app)

**Status:** ✅ **CONNECTED AND WORKING!**

---

## 📡 How the Connection Works

```
┌──────────────┐
│   Windows    │
│  Computer    │
│              │
│  Frida CLI   │  ◄──── You run scripts here
└──────┬───────┘
       │
       │ USB Connection
       │
       ▼
┌──────────────┐
│   Pixel 4    │
│  (Android)   │
│              │
│  Frida       │  ◄──── Frida server running
│  Server      │
│              │
│  ┌────────┐  │
│  │ Dasher │  │  ◄──── Target app
│  │  App   │  │
│  └────────┘  │
└──────────────┘
```

### No SSH Tunnel Needed!

**Important Discovery:** The Frida connection works **directly over USB** via ADB. You don't need the 3uTools SSH tunnel for Frida operations.

**3uTools SSH tunnel (port 22)** was for:
- Manual SSH access to the device
- File transfers
- Manual Frida server management

**Frida USB connection** provides:
- Direct app instrumentation
- Faster communication
- Automatic device detection
- No network configuration needed

---

## ✅ Verified Working Commands

### 1. List Running Apps
```bash
python -m frida_tools.ps -Uai
```

**Output:**
```
PID  Name                           Identifier
----  -----------------------------  ---------------------------
  -   Dasher                         com.doordash.driverapp
  -   DoorDash                       com.dd.doordash
  -   (other apps...)
```

### 2. Get Device Info
```python
python -c "import frida; device = frida.get_usb_device(); print(f'Device: {device.name}'); print(f'ID: {device.id}')"
```

**Output:**
```
Device: Pixel 4
ID: 1AEAFS000010KE
```

### 3. Attach to Running App
```bash
python frida-attach.py <PID> <script.js>
```

### 4. Spawn App with Script
```bash
python frida-spawn.py com.doordash.driverapp <script.js>
```

---

## 🎮 Interactive REPL (NEW!)

I've created a powerful interactive Frida development environment!

### Launch the REPL

```bash
# Attach to running Dasher app
python live-frida-repl.py com.doordash.driverapp

# Spawn Dasher app
python live-frida-repl.py com.doordash.driverapp --spawn
```

### REPL Commands

```
frida> load <template>    - Load script template
frida> reload             - Reload current script
frida> save <file>        - Save current script
frida> run <file>         - Load and run script from file
frida> js <code>          - Execute JavaScript in app
frida> quit               - Exit REPL
```

### Available Templates

| Template | Description |
|----------|-------------|
| `basic` | Basic Frida script template |
| `network` | Network request monitoring |
| `ssl-unpin` | SSL certificate unpinning |
| `proxy` | Proxy configuration (HTTP Toolkit) |
| `all` | Complete monitoring + SSL + Proxy |

### Example REPL Session

```bash
$ python live-frida-repl.py com.doordash.driverapp

[10:23:45] [INFO] Connecting to USB device...
[10:23:46] [SUCCESS] Connected to: Pixel 4 (1AEAFS000010KE)
[10:23:46] [INFO] Attaching to com.doordash.driverapp...
[10:23:47] [SUCCESS] Attached successfully
[10:23:47] [INFO] Loading default 'all' template...
[10:23:47] [SUCCESS] Script loaded successfully
[10:23:47] [SCRIPT] [*] Complete monitoring + SSL bypass + Proxy script loaded
[10:23:47] [SCRIPT] [*] Java environment ready
[10:23:47] [SCRIPT] [*] Android version: 13
[10:23:47] [SCRIPT] [+] SSLContext.init() bypassed
[10:23:47] [SCRIPT] [+] Proxy configured: 192.168.50.9:8000

Commands:
  load <template>  - Load script template
  reload           - Reload current script
  save <file>      - Save current script
  run <file>       - Load and run script from file
  js <code>        - Execute JavaScript in app context
  quit             - Exit REPL

frida> load network
[10:24:10] [SUCCESS] Script loaded successfully
[10:24:10] [SCRIPT] [*] Network monitoring script loaded
[10:24:10] [SCRIPT] [+] Found OkHttp3

frida> js console.log("Hello from Dasher!")
[10:24:32] [SCRIPT] Hello from Dasher!

frida> save my-dasher-script.js
[10:24:45] [SUCCESS] Script saved to my-dasher-script.js

frida> quit
[10:25:00] [INFO] Exiting REPL...
```

---

## 📜 Creating Custom Frida Scripts

### Script Structure for Android

```javascript
console.log("[*] Custom Frida script started");

// Wait for Java environment to be ready
Java.perform(function() {
    console.log("[*] Java environment ready");
    console.log("[*] Android version: " + Java.androidVersion);

    // Your hooks go here
    try {
        var ClassName = Java.use('com.example.ClassName');
        ClassName.methodName.implementation = function(arg) {
            console.log("[HOOK] methodName called with: " + arg);
            return this.methodName(arg);
        };
    } catch(e) {
        console.log("[ERROR] " + e);
    }
});
```

### Example 1: Monitor All Network Requests

```javascript
Java.perform(function() {
    // Hook OkHttp3 (most common in Android apps)
    try {
        var Request = Java.use('okhttp3.Request');
        Request.url.implementation = function() {
            var url = this.url();
            console.log("[→ REQUEST] " + url.toString());

            // Send to HTTP Toolkit
            send({
                type: 'request',
                url: url.toString(),
                method: this.method(),
                timestamp: Date.now()
            });

            return url;
        };

        var Response = Java.use('okhttp3.Response');
        Response.code.implementation = function() {
            var code = this.code();
            var url = this.request().url().toString();
            console.log("[← RESPONSE] " + code + " " + url);

            return code;
        };

        console.log("[+] OkHttp3 network monitoring enabled");
    } catch(e) {
        console.log("[!] OkHttp3 not found: " + e);
    }

    // Hook HttpURLConnection (backup/legacy)
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getURL.implementation = function() {
            var url = this.getURL();
            console.log("[→ REQUEST] " + url.toString());
            return url;
        };

        console.log("[+] HttpURLConnection monitoring enabled");
    } catch(e) {
        console.log("[!] HttpURLConnection hook failed");
    }
});
```

### Example 2: SSL Certificate Unpinning

```javascript
Java.perform(function() {
    console.log("[*] Starting SSL unpinning...");

    // Method 1: SSLContext bypass
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function(km, tm, sr) {
            console.log("[+] SSLContext.init() bypassed");
            this.init(km, null, sr);  // Pass null for TrustManager
        };
    } catch(e) {
        console.log("[!] SSLContext bypass failed: " + e);
    }

    // Method 2: TrustManager bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.frida.FridaTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    // Accept all
                },
                checkServerTrusted: function(chain, authType) {
                    // Accept all
                },
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });
        console.log("[+] Custom TrustManager registered");
    } catch(e) {
        console.log("[!] TrustManager bypass failed: " + e);
    }

    // Method 3: OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload(
            'java.lang.String',
            'java.util.List'
        ).implementation = function(hostname, peerCertificates) {
            console.log("[+] Certificate pinning bypassed for: " + hostname);
            return;  // Don't check, just return
        };
    } catch(e) {
        console.log("[!] OkHttp3 CertificatePinner not found: " + e);
    }

    console.log("[+] SSL unpinning complete");
});
```

### Example 3: HTTP Toolkit Proxy Configuration

```javascript
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

Java.perform(function() {
    console.log("[*] Configuring HTTP Toolkit proxy...");

    // Set system properties
    try {
        var System = Java.use('java.lang.System');
        System.setProperty("http.proxyHost", proxyHost);
        System.setProperty("http.proxyPort", proxyPort.toString());
        System.setProperty("https.proxyHost", proxyHost);
        System.setProperty("https.proxyPort", proxyPort.toString());
        console.log("[+] System proxy set: " + proxyHost + ":" + proxyPort);
    } catch(e) {
        console.log("[!] System proxy failed: " + e);
    }

    // Configure OkHttpClient to use proxy
    try {
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        var Proxy = Java.use('java.net.Proxy');
        var Type = Java.use('java.net.Proxy$Type');
        var InetSocketAddress = Java.use('java.net.InetSocketAddress');

        Builder.build.implementation = function() {
            var proxy = Proxy.$new(
                Type.HTTP.value,
                InetSocketAddress.$new(proxyHost, proxyPort)
            );
            this.proxy(proxy);
            console.log("[+] OkHttpClient proxy configured");
            return this.build();
        };
    } catch(e) {
        console.log("[!] OkHttpClient proxy failed: " + e);
    }

    console.log("[+] Proxy configuration complete");
});
```

### Example 4: Complete Monitoring + SSL + Proxy

```javascript
// COMPLETE SCRIPT - Copy this for HTTP Toolkit integration
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

console.log("[*] Dasher Complete Monitoring Script");
console.log("[*] Proxy: " + proxyHost + ":" + proxyPort);

Java.perform(function() {
    console.log("[*] Java environment ready");
    console.log("[*] Android version: " + Java.androidVersion);

    // ===== SSL UNPINNING =====
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            console.log("[+] SSLContext bypassed");
            this.init(km, null, sr);
        };

        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] Cert pinning bypassed: " + hostname);
            return;
        };
    } catch(e) {
        console.log("[!] SSL bypass error: " + e);
    }

    // ===== PROXY SETUP =====
    try {
        var System = Java.use('java.lang.System');
        System.setProperty("http.proxyHost", proxyHost);
        System.setProperty("http.proxyPort", proxyPort.toString());
        System.setProperty("https.proxyHost", proxyHost);
        System.setProperty("https.proxyPort", proxyPort.toString());
        console.log("[+] Proxy configured: " + proxyHost + ":" + proxyPort);
    } catch(e) {
        console.log("[!] Proxy error: " + e);
    }

    // ===== NETWORK MONITORING =====
    try {
        var Request = Java.use('okhttp3.Request');
        Request.url.implementation = function() {
            var url = this.url();
            send({type: 'request', url: url.toString(), method: this.method()});
            console.log("[→] " + this.method() + " " + url.toString());
            return url;
        };

        var Response = Java.use('okhttp3.Response');
        Response.code.implementation = function() {
            var code = this.code();
            var url = this.request().url().toString();
            send({type: 'response', code: code, url: url});
            console.log("[←] " + code + " " + url);
            return code;
        };
    } catch(e) {
        console.log("[!] Network monitoring error: " + e);
    }

    console.log("[+] All hooks installed successfully!");
    console.log("[+] Traffic should now appear in HTTP Toolkit");
});
```

---

## 🛠️ Quick Launcher Scripts

### Launch Dasher with Monitoring

Create: `DASHER-LIVE-MONITOR.bat`

```batch
@echo off
echo Starting Dasher Live Monitor...
python live-frida-repl.py com.doordash.driverapp
pause
```

### Spawn Dasher with Full Script

Create: `DASHER-SPAWN-MONITOR.bat`

```batch
@echo off
echo Spawning Dasher with monitoring...
python live-frida-repl.py com.doordash.driverapp --spawn
pause
```

---

## 🎯 Workflow for Live Script Development

### Method 1: Interactive REPL (Recommended)

```bash
# 1. Start REPL
python live-frida-repl.py com.doordash.driverapp

# 2. Load template
frida> load all

# 3. Test and iterate
frida> js console.log("Testing...")

# 4. Save your work
frida> save my-script.js

# 5. Edit externally if needed
# (Edit my-script.js in your editor)

# 6. Reload
frida> run my-script.js
```

### Method 2: File-based Development

```bash
# 1. Create/edit script file
notepad my-dasher-script.js

# 2. Test it
python frida-spawn.py com.doordash.driverapp my-dasher-script.js

# 3. Edit and repeat
# (Make changes in notepad)

# 4. Test again
python frida-spawn.py com.doordash.driverapp my-dasher-script.js
```

### Method 3: Live REPL + Editor

```bash
# Terminal 1: Run REPL
python live-frida-repl.py com.doordash.driverapp
frida> load all
frida> save current.js

# Terminal 2: Edit in real-time
notepad current.js

# Back to Terminal 1: Reload after edits
frida> run current.js
```

---

## 📊 Testing Your Setup

### Step 1: Verify Frida Connection

```bash
python -m frida_tools.ps -U
```

**Expected:** List of running processes

### Step 2: Verify App is Detected

```bash
python -m frida_tools.ps -Uai | grep -i dasher
```

**Expected:**
```
  -  Dasher                         com.doordash.driverapp
```

### Step 3: Test Basic Script

Create `test.js`:
```javascript
console.log("[*] Test script loaded!");
Java.perform(function() {
    console.log("[*] Java ready - Android " + Java.androidVersion);
});
```

Run:
```bash
python frida-spawn.py com.doordash.driverapp test.js
```

**Expected Output:**
```
[+] Bundle ID: com.doordash.driverapp
[+] Script: test.js
[+] Connected to device: Pixel 4
[+] Spawning com.doordash.driverapp...
[*] Test script loaded!
[*] Java ready - Android 13
```

### Step 4: Test HTTP Toolkit Integration

```bash
# 1. Open HTTP Toolkit on 192.168.50.9:8000
# 2. Run REPL with proxy script
python live-frida-repl.py com.doordash.driverapp
frida> load all

# 3. Use Dasher app (make network requests)
# 4. Check HTTP Toolkit for captured traffic
```

---

## 🚀 What You Can Do Now

### ✅ Observe
- Monitor all network requests in real-time
- View request/response headers and bodies
- Track API calls and data flows
- Analyze authentication mechanisms

### ✅ Manipulate
- Modify request parameters before sending
- Change response data before app processes it
- Block specific requests (analytics, tracking)
- Inject custom headers or data

### ✅ Bypass
- SSL certificate pinning
- Root/jailbreak detection
- App integrity checks
- Network restrictions

### ✅ Debug
- Test different API payloads
- Understand app logic flow
- Identify security vulnerabilities
- Reverse engineer protocols

---

## 📝 Script Template Library

Save these in `frida-scripts/` directory:

| File | Purpose |
|------|---------|
| `basic-monitor.js` | Basic network monitoring |
| `ssl-unpin-only.js` | SSL unpinning without proxy |
| `proxy-only.js` | Proxy config without SSL bypass |
| `complete-monitor.js` | Full monitoring + SSL + Proxy |
| `auth-logger.js` | Log authentication tokens |
| `request-modifier.js` | Modify requests before sending |

---

## 🎓 Next Steps

1. **Start with REPL:** `python live-frida-repl.py com.doordash.driverapp`
2. **Load "all" template:** `frida> load all`
3. **Open HTTP Toolkit:** Monitor at `http://192.168.50.9:8000`
4. **Use Dasher app:** Make requests and watch traffic
5. **Experiment:** Try different templates and custom scripts
6. **Save your work:** `frida> save my-custom-script.js`

---

## 🔧 Troubleshooting

### Issue: "Failed to spawn"
**Solution:** App might be running. Kill it first or use attach mode.

### Issue: "Java.perform is not a function"
**Solution:** Script loaded before Java VM ready. Wrap code in `Java.perform()`.

### Issue: "No devices found"
**Solution:** Check USB connection and ADB:
```bash
adb devices
```

### Issue: "Class not found"
**Solution:** Class name might be obfuscated. Use `Java.enumerateLoadedClasses()` to find it.

---

**You're all set to develop Frida scripts live! 🚀**
