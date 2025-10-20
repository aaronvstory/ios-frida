# Frida Live Network Monitor 🚀

> Bypass HTTP Toolkit proxy detection issues with direct Frida injection for iOS apps

## Quick Start (3 Steps)

### 1. Prerequisites ✅
- 3uTools SSH tunnel opened (you already have this!)
- Jailbroken iPhone SE2 (iOS 16.3.1 Dopamine)
- HTTP Toolkit running at `192.168.50.9:8000`
- DoorDash Dasher app installed

### 2. Launch the Monitor
```bash
FRIDA-LIVE-MONITOR.bat
```

### 3. Choose Your Mode
- **SPAWN MODE** (Recommended) - Restarts app, most reliable
- **ATTACH MODE** - Keeps session alive, may need refresh

**That's it!** Traffic will appear in HTTP Toolkit.

---

## What This Does

### The Problem
HTTP Toolkit error when trying to intercept:
```
Failed to intercept com.doordash.dasher: Proxy IP detection on target device
failed for port 8000 and IPs ["192.168.50.141 (unreachable-from"]
```

### Our Solution
✅ Direct SSH tunnel via 3uTools
✅ Frida script injection (no iOS proxy settings needed)
✅ SSL pinning bypass
✅ Traffic routing to HTTP Toolkit

---

## Project Structure

```
📦 ios frida/
├── 🎯 FRIDA-LIVE-MONITOR.bat          ← START HERE (main launcher)
├── 🐍 live-network-monitor.py          ← Advanced Python monitor
├── 📖 LIVE-MANIPULATION-GUIDE.md       ← Complete documentation
├── 🔧 QUICK-START.md                   ← Fast setup guide
│
├── 🔑 Core Files
│   ├── frida-spawn.py                  ← Spawn mode handler
│   ├── frida-attach.py                 ← Attach mode handler
│   ├── plink.exe                       ← SSH tunnel utility
│   └── requirements.txt                ← Python dependencies
│
├── 📁 config/
│   └── frida-config.json               ← Network & app settings
│
├── 📜 frida-interception-and-unpinning/
│   ├── enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js  ← Best for spawn
│   ├── attach-mode-proxy.js                                       ← Best for attach
│   └── ... (other working scripts)
│
├── 📊 logs/                            ← Monitor logs
└── 📦 archive/                         ← Old files (if needed)
    ├── old-launchers/
    ├── old-scripts/
    └── old-docs/
```

---

## Common Commands

### Basic Usage
```bash
# Main launcher (easiest)
FRIDA-LIVE-MONITOR.bat

# Advanced Python monitor
python live-network-monitor.py com.doordash.dasher

# Attach to running app (PID 1234)
python live-network-monitor.py com.doordash.dasher --attach 1234

# Custom log file
python live-network-monitor.py com.doordash.dasher --log-file my-traffic.log
```

### Manual Frida Operations
```bash
# Spawn mode (app restarts)
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js

# Attach mode (stay logged in)
python frida-attach.py [PID] frida-interception-and-unpinning\attach-mode-proxy.js

# Find app PID
frida-ps -Uai | findstr "dasher"
```

### SSH Tunnel Management
```bash
# Test SSH connection (via 3uTools tunnel at port 10022)
plink.exe -P 10022 root@127.0.0.1 -pw alpine "echo Connected"

# Start Frida server on iPhone
plink.exe -P 10022 root@127.0.0.1 -pw alpine "/usr/sbin/frida-server &"

# Check Frida server status
plink.exe -P 10022 root@127.0.0.1 -pw alpine "ps aux | grep frida-server"
```

---

## What You Can Do

### 🔍 Observe
- All HTTP/HTTPS requests and responses
- Headers, bodies, timing
- API endpoints and authentication tokens
- Real-time traffic analysis

### 🛠️ Manipulate
- Modify request headers (User-Agent, etc.)
- Change request/response bodies
- Block specific requests (analytics, tracking)
- Inject custom headers
- Simulate network conditions

### 🐛 Debug
- See exact API calls
- Understand authentication flow
- Test different payloads
- Replay and modify requests

---

## Troubleshooting

### Issue: SSH Connection Failed
```bash
# Solution: Re-open SSH tunnel in 3uTools
# Expected: "Succeeded to open SSH tunnel" at 127.0.0.1
```

### Issue: No Traffic in HTTP Toolkit
**Checklist:**
1. HTTP Toolkit running on `192.168.50.9:8000`
2. You see "Proxy configured" in Frida console
3. App is making requests (try refreshing)
4. SSL bypass messages appeared

**Debug:**
```bash
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\proxy-diagnostics.js
```

### Issue: App Not Found (Attach Mode)
```bash
# Make sure app is running first
frida-ps -Uai | findstr "dasher"
```

### Issue: "Decode Error" Messages
This is normal! We use the "fixed" script which handles binary data correctly.

---

## Key Files Explained

| File | Purpose |
|------|---------|
| `FRIDA-LIVE-MONITOR.bat` | **Main launcher** - Use this! |
| `live-network-monitor.py` | Advanced monitor with logging |
| `LIVE-MANIPULATION-GUIDE.md` | **Complete guide** - Read this for advanced usage |
| `frida-spawn.py` | Core spawn mode functionality |
| `frida-attach.py` | Core attach mode functionality |
| `config/frida-config.json` | Network and app configuration |
| `enhanced-...-fixed.js` | Best SSL bypass script (spawn mode) |
| `attach-mode-proxy.js` | Best script for attach mode |

---

## Advanced Features

### Live Request Modification
Edit `frida-interception-and-unpinning/enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js` to add custom hooks:

```javascript
// Example: Log all requests
Interceptor.attach(NSURLSessionTask['- resume'].implementation, {
    onEnter: function(args) {
        var task = new ObjC.Object(args[0]);
        var request = task.currentRequest();
        var url = request.URL().absoluteString().toString();
        console.log("[REQUEST] " + url);
    }
});
```

### HTTP Toolkit Integration
- Set breakpoints on specific URLs
- Modify requests/responses in real-time
- Replay requests with modifications
- Export captured traffic

### Continuous Monitoring
```bash
# Run in background and monitor logs
start /B python live-network-monitor.py com.doordash.dasher --log-file continuous.log
tail -f continuous.log
```

---

## Documentation

- 📖 **LIVE-MANIPULATION-GUIDE.md** - Complete guide for observation & manipulation
- 🔧 **QUICK-START.md** - Fast setup instructions
- 📋 **CLEANUP-PLAN.md** - Workspace organization details
- 🎯 **CLAUDE.md** - Project technical overview

---

## Dependencies

### Python Packages
```bash
pip install -r requirements.txt
```

Required:
- frida-tools >= 12.0.0
- frida >= 16.0.0
- colorama >= 0.4.6

### System Requirements
- Windows (for .bat scripts)
- Python 3.7+
- Frida CLI tools
- 3uTools (for SSH tunnel)
- HTTP Toolkit

---

## Network Configuration

Default settings (in `config/frida-config.json`):

```json
{
  "Network": {
    "iPhoneIP": "192.168.50.113",
    "WindowsIP": "192.168.50.9",
    "ProxyPort": 8000,
    "SSHPort": 10022,
    "SSHUser": "root",
    "SSHPass": "alpine"
  },
  "Apps": {
    "DoorDashDasher": {
      "Name": "DoorDash Dasher",
      "BundleID": "com.doordash.dasher"
    }
  }
}
```

---

## Tips for Success

1. ✅ **Start with SPAWN mode** - Most reliable for initial setup
2. ✅ **Watch the console** - Confirms proxy config and SSL bypass
3. ✅ **Use attach mode for active sessions** - Keeps you logged in
4. ✅ **Refresh the app** - In attach mode, pull to refresh after injection
5. ✅ **Check HTTP Toolkit** - Should show "Intercepted" status

---

## Support

For issues or questions:
1. Check **LIVE-MANIPULATION-GUIDE.md** for detailed troubleshooting
2. Review **QUICK-START.md** for setup verification
3. Check `logs/` directory for detailed output
4. Verify configuration in `config/frida-config.json`

---

## License & Security

⚠️ **For security research and authorized testing only**

This tool is for:
- ✅ Security research on your own devices
- ✅ App debugging and development
- ✅ Network analysis and testing

Not for:
- ❌ Unauthorized access
- ❌ Bypassing app security for malicious purposes
- ❌ Production environment attacks

Default iOS root password (`alpine`) should be changed on production devices.

---

**Happy Monitoring! 🎉**

For detailed usage examples and advanced techniques, see **LIVE-MANIPULATION-GUIDE.md**
