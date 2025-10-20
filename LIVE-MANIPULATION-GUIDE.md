# Live Network Observation & Manipulation Guide

## Overview

This guide explains how to observe and manipulate iOS app network traffic in real-time using Frida, bypassing HTTP Toolkit's proxy detection issues.

## Quick Start

### Prerequisites (You Already Have These!)

1. ✅ **3uTools SSH Tunnel** - Already opened at `127.0.0.1`
2. ✅ **Jailbroken iPhone SE2** - iOS 16.3.1 Dopamine RootHide
3. ✅ **HTTP Toolkit** - Running at `192.168.50.9:8000`
4. ✅ **Frida** - Installed on both Windows and iPhone

### One-Command Launch

```bash
# Simply run this bat file
FRIDA-LIVE-MONITOR.bat
```

This unified script will:
- ✅ Verify SSH tunnel connection
- ✅ Start Frida server on iPhone (if needed)
- ✅ Let you choose SPAWN or ATTACH mode
- ✅ Inject proxy configuration and SSL bypass
- ✅ Start live network monitoring

---

## Understanding the Setup

### The Problem HTTP Toolkit Had

**HTTP Toolkit Error:**
```
Failed to intercept com.doordash.dasher: Proxy IP detection on target device
failed for port 8000 and IPs ["192.168.50.141 (unreachable-from"]
```

**Why it failed:**
- HTTP Toolkit tries to auto-configure iOS proxy settings
- Jailbreak detection or network restrictions blocked it
- App couldn't reach the proxy IP from the device

### Our Solution: Direct Frida Injection

Instead of relying on HTTP Toolkit's auto-config, we:

1. **Use 3uTools SSH tunnel** → Direct access to iPhone via `127.0.0.1:10022`
2. **Inject Frida script** → Programmatically set proxy in app's memory
3. **Bypass SSL pinning** → Allow HTTP Toolkit to decrypt HTTPS
4. **Route traffic** → All requests go through `192.168.50.9:8000`

---

## How to Observe Traffic Live

### Step 1: Launch the Monitor

```bash
FRIDA-LIVE-MONITOR.bat
```

### Step 2: Choose Your Mode

**Option 1: SPAWN MODE (Recommended)**
- App restarts (you'll be logged out)
- Most reliable for capturing traffic
- Best for initial setup/testing

**Option 2: ATTACH MODE**
- App stays running (you stay logged in)
- Good for ongoing monitoring
- May need to refresh app to activate proxy

### Step 3: Watch the Console

You'll see messages like:
```
[+] Connected to device: iPhone
[+] Spawning com.doordash.dasher...
[*] Configuring proxy for defaultSessionConfiguration
[+] Proxy configured: 192.168.50.9:8000
[*] Bypassing SSL pinning in NSURLSession
[*] Bypassing SecTrustEvaluate
[+] Script loaded successfully
```

### Step 4: Open HTTP Toolkit

Traffic should now appear in HTTP Toolkit UI at `http://192.168.50.9:8000`

You'll see:
- All HTTP/HTTPS requests
- Request/response headers
- Request/response bodies
- Timing information

---

## How to Manipulate Traffic Live

### Method 1: Using HTTP Toolkit UI (Easiest)

**Rewrite Requests:**
1. In HTTP Toolkit, click on a captured request
2. Click "Edit & Resend" button
3. Modify headers, body, method, etc.
4. Click "Send"

**Set Breakpoints:**
1. Go to "Mock" tab in HTTP Toolkit
2. Add a rule for specific URL pattern
3. Choose action:
   - Passthrough (with modifications)
   - Return custom response
   - Add delay
   - Close connection

**Example: Change API Response**
```javascript
// In HTTP Toolkit Mock Rules:
Match: URL contains "api.doordash.com/v1/consumer/me"
Action: Return custom response
Status: 200
Body: {"id": "12345", "name": "Modified User", "email": "test@example.com"}
```

### Method 2: Modify the Frida Script (Advanced)

Edit `frida-interception-and-unpinning/enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js`

**Example: Log All Request URLs**
```javascript
// Add this after the proxy configuration:

// Hook NSURLSessionTask to log requests
if (ObjC.classes.NSURLSessionTask) {
    var NSURLSessionTask = ObjC.classes.NSURLSessionTask;
    var resume = NSURLSessionTask['- resume'];

    if (resume) {
        Interceptor.attach(resume.implementation, {
            onEnter: function(args) {
                try {
                    var task = new ObjC.Object(args[0]);
                    var request = task.currentRequest();
                    if (request) {
                        var url = request.URL().absoluteString().toString();
                        var method = request.HTTPMethod().toString();
                        console.log("[REQUEST] " + method + " " + url);
                    }
                } catch (e) {}
            }
        });
    }
}
```

**Example: Modify Request Headers**
```javascript
// Intercept and modify User-Agent header
Interceptor.attach(ObjC.classes.NSMutableURLRequest['- setValue:forHTTPHeaderField:'].implementation, {
    onEnter: function(args) {
        var headerField = ObjC.Object(args[3]).toString();

        if (headerField === "User-Agent") {
            var newUserAgent = ObjC.classes.NSString.stringWithString_("CustomUserAgent/1.0");
            args[2] = newUserAgent;
            console.log("[MODIFIED] Changed User-Agent to: CustomUserAgent/1.0");
        }
    }
});
```

**Example: Block Specific Requests**
```javascript
// Block requests to analytics endpoints
if (ObjC.classes.NSURLSessionTask) {
    var NSURLSessionTask = ObjC.classes.NSURLSessionTask;
    var resume = NSURLSessionTask['- resume'];

    if (resume) {
        Interceptor.attach(resume.implementation, {
            onEnter: function(args) {
                try {
                    var task = new ObjC.Object(args[0]);
                    var request = task.currentRequest();
                    if (request) {
                        var url = request.URL().absoluteString().toString();

                        // Block analytics requests
                        if (url.includes("analytics.doordash.com") ||
                            url.includes("segment.com")) {
                            console.log("[BLOCKED] Analytics request: " + url);
                            task.cancel();
                        }
                    }
                } catch (e) {}
            }
        });
    }
}
```

**Example: Modify Response Data**
```javascript
// Hook NSURLSession completion handlers to modify responses
if (ObjC.classes.NSURLSession) {
    var originalMethod = ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'];

    if (originalMethod) {
        Interceptor.attach(originalMethod.implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();

                // Wrap the original completion handler
                var originalHandler = new ObjC.Block(args[3]);
                var newHandler = new ObjC.Block({
                    retType: 'void',
                    argTypes: ['object', 'object', 'object'],
                    implementation: function(data, response, error) {
                        if (url.includes("api.doordash.com")) {
                            try {
                                // Modify the response data here
                                var jsonData = ObjC.classes.NSJSONSerialization.JSONObjectWithData_options_error_(data, 0, NULL);
                                console.log("[RESPONSE] Modified response for: " + url);
                            } catch (e) {}
                        }

                        // Call original handler
                        originalHandler(data, response, error);
                    }
                });

                args[3] = newHandler;
            }
        });
    }
}
```

### Method 3: Advanced Python Monitor (Live Logging)

Use the advanced monitoring script:

```bash
# Basic usage
python live-network-monitor.py com.doordash.dasher

# Attach to running app
python live-network-monitor.py com.doordash.dasher --attach 1234

# Custom log file
python live-network-monitor.py com.doordash.dasher --log-file my-traffic.log
```

This provides:
- ✅ Colored console output
- ✅ Automatic logging to file
- ✅ Request/response tracking
- ✅ Statistics on exit

---

## Troubleshooting

### Issue: SSH Connection Failed

**Solution:**
```bash
# In 3uTools, click "Open SSH Tunnel" again
# You should see: "Succeeded to open SSH tunnel"
# Then re-run FRIDA-LIVE-MONITOR.bat
```

### Issue: Frida Server Not Running

**Solution:**
```bash
# The script auto-starts it, but if manual start needed:
plink.exe -P 10022 root@127.0.0.1 -pw alpine "/usr/sbin/frida-server &"
```

### Issue: App Not Found (Attach Mode)

**Solution:**
```bash
# Make sure Dasher app is open and running
# Check if it's running:
frida-ps -Uai | findstr "dasher"
```

### Issue: No Traffic in HTTP Toolkit

**Checklist:**
1. ✅ HTTP Toolkit is running on `192.168.50.9:8000`
2. ✅ You see "Proxy configured" in Frida console
3. ✅ App is making network requests (try refreshing)
4. ✅ SSL bypass messages appeared

**Debug:**
```bash
# Use the diagnostics script
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\proxy-diagnostics.js
```

### Issue: "Decode Error" Messages

**This is NORMAL!** We use the "fixed" script which handles binary data correctly.

If you see decode errors, switch scripts:
```bash
# Edit FRIDA-LIVE-MONITOR.bat and change:
set SCRIPT_PATH=frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js
```

---

## Advanced Techniques

### 1. Live Request Replay

Capture a request in HTTP Toolkit, then replay it with modifications:

```bash
# In HTTP Toolkit:
1. Right-click on captured request
2. Select "Edit & Resend"
3. Modify as needed
4. Click "Send"
```

### 2. Custom Frida Hooks

Create your own monitoring script:

```javascript
// my-custom-hooks.js
console.log("[*] Custom hooks loading...");

// Hook specific class methods
if (ObjC.available) {
    // Example: Hook DoorDash-specific classes
    var DoorDashAPI = ObjC.classes.DDAPIManager; // Replace with actual class

    if (DoorDashAPI) {
        var makeRequest = DoorDashAPI['- makeRequest:'];

        Interceptor.attach(makeRequest.implementation, {
            onEnter: function(args) {
                console.log("[DOORDASH API] Request intercepted!");
            }
        });
    }
}
```

Then use it:
```bash
python frida-spawn.py com.doordash.dasher my-custom-hooks.js
```

### 3. Network Condition Simulation

Add delays or failures in the Frida script:

```javascript
// Simulate slow network
Interceptor.attach(NSURLSessionTask['- resume'].implementation, {
    onEnter: function(args) {
        // Add 2 second delay
        Thread.sleep(2);
        console.log("[NETWORK] Simulated 2s delay");
    }
});
```

### 4. Continuous Monitoring

Run the monitor in the background:

```bash
# Start monitoring
start /B python live-network-monitor.py com.doordash.dasher --log-file continuous.log

# Monitor the log file in real-time
tail -f continuous.log
```

---

## File Reference

### Main Scripts
- `FRIDA-LIVE-MONITOR.bat` - **Unified launcher** (USE THIS!)
- `live-network-monitor.py` - Advanced Python monitor
- `frida-spawn.py` - Basic spawn mode
- `frida-attach.py` - Basic attach mode

### Frida JS Scripts (in `frida-interception-and-unpinning/`)
- `enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js` - **Best for spawn mode**
- `attach-mode-proxy.js` - **Best for attach mode**
- `proxy-diagnostics.js` - Troubleshooting
- `universal-ssl-pinning-bypass-with-proxy.js` - Standard version

### Configuration
- `config/frida-config.json` - Network and app settings

### Logs
- `logs/` - All monitoring logs saved here

---

## Tips for Success

1. **Always use SPAWN mode first** - It's most reliable for initial setup
2. **Watch the console** - SSL bypass and proxy config messages confirm success
3. **Refresh the app** - In attach mode, pull to refresh after script loads
4. **Check HTTP Toolkit** - Should show "Intercepted" status for the app
5. **Use Python monitor** - For better logging and statistics

---

## What You Can Do Now

✅ **Observe:**
- All HTTP/HTTPS requests and responses
- Request/response headers and bodies
- API endpoints and payloads
- Authentication tokens
- Timing and performance metrics

✅ **Manipulate:**
- Modify request headers (User-Agent, etc.)
- Change request bodies (POST data)
- Alter response data
- Block specific requests (analytics, tracking)
- Inject custom headers
- Simulate network conditions

✅ **Debug:**
- See exactly what the app is sending
- Identify API endpoints
- Understand authentication flow
- Test different request payloads
- Replay and modify requests

---

## Need More Help?

Check these files:
- `CLAUDE.md` - Project documentation
- `TEST-README.md` - Testing guide
- `frida-interception-and-unpinning/` - All available scripts

Or modify the scripts directly - they're well-commented and easy to customize!
