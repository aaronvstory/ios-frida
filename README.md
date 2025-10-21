# Frida Live Development Framework 🚀

[![Platform](https://img.shields.io/badge/Platform-iOS%20%7C%20Android-blue.svg)](https://github.com/aaronvstory/ios-frida)
[![Frida](https://img.shields.io/badge/Frida-16.0%2B-orange.svg)](https://frida.re/)
[![Python](https://img.shields.io/badge/Python-3.7%2B-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Research%20Only-red.svg)](#license--security)

> Comprehensive mobile app interception toolkit for security research and network traffic analysis. Supports both iOS (SSH tunnel) and Android (USB/ADB) with live script development capabilities and HTTP Toolkit integration.

## 🎯 Quick Start

### Android (Primary - Recommended)

**One-Click Launch:**
```bash
DASHER-LIVE-MONITOR.bat
```

**Or Interactive REPL:**
```bash
python live-frida-repl.py com.doordash.driverapp
```

**Prerequisites:**
- ✅ Android device connected via USB (Pixel 4 tested)
- ✅ USB debugging enabled
- ✅ Frida installed (`pip install frida-tools`)

### iOS (Legacy - SSH Tunnel)

**Launch:**
```bash
FRIDA-LIVE-MONITOR-THIS-WORKS.bat
```

**Prerequisites:**
- ✅ 3uTools SSH tunnel opened (127.0.0.1:22 → iPhone:22)
- ✅ Jailbroken iPhone (iOS 16.3.1+ with Dopamine/RootHide tested)
- ✅ Frida server installed on device

---

## ✨ Features

### Core Capabilities
- 🔥 **Live Interactive REPL** - Hot-reload Frida scripts during development
- 📱 **Dual Platform Support** - Android (USB) and iOS (SSH tunnel)
- 🔓 **SSL Pinning Bypass** - Universal SSL/TLS certificate unpinning
- 🌐 **HTTP Toolkit Integration** - Route and inspect HTTPS traffic
- 🔍 **Network Monitoring** - Real-time request/response logging
- ⚡ **Hot Reload** - Save, edit, and reload scripts without restart
- 📊 **Built-in Templates** - Ready-to-use script templates for common tasks

### What Problems Does This Solve?

**Before:** HTTP Toolkit proxy detection fails on jailbroken/rooted devices
```
Error: Proxy IP detection on target device failed
```

**After:** Direct Frida injection bypasses detection entirely
```
✅ Frida connects via USB (Android) or SSH tunnel (iOS)
✅ Injects proxy config into app memory directly
✅ Bypasses SSL pinning
✅ Routes all traffic to HTTP Toolkit
```

---

## 📦 Installation

### 1. Clone Repository
```bash
git clone https://github.com/aaronvstory/ios-frida.git
cd ios-frida
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

**Required packages:**
- `frida-tools >= 12.0.0`
- `frida >= 16.0.0`
- `colorama >= 0.4.6`

### 3. Platform-Specific Setup

#### Android
```bash
# Enable USB debugging on device
# Connect device via USB
# Verify connection
adb devices
python -m frida_tools.ps -U
```

#### iOS
```bash
# Install Frida server on jailbroken iPhone
# Open SSH tunnel via 3uTools
# Verify: plink.exe -P 10022 root@127.0.0.1 -pw alpine "echo Connected"
```

---

## 📁 Project Structure

```
📦 ios-frida/
│
├── 🎯 Android Launchers
│   ├── DASHER-LIVE-MONITOR.bat        ← Primary: Attach to running app
│   ├── DASHER-SPAWN-MONITOR.bat       ← Spawn fresh app instance
│   └── live-frida-repl.py             ← 🔥 Interactive REPL (RECOMMENDED)
│
├── 🍎 iOS Launchers
│   ├── FRIDA-LIVE-MONITOR-THIS-WORKS.bat  ← iOS SSH-based launcher
│   ├── frida-spawn-ios.py             ← iOS spawn variant
│   └── frida-spawn-ios-direct.py      ← iOS direct spawn
│
├── 🐍 Core Python Scripts
│   ├── frida-spawn.py                 ← Spawn mode (restarts app)
│   ├── frida-attach.py                ← Attach mode (preserves session)
│   ├── live-monitor.py                ← Monitor tool
│   └── live-network-monitor.py        ← Advanced network monitor
│
├── 📜 Injection Scripts
│   └── frida-interception-and-unpinning/
│       ├── enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js (iOS)
│       ├── attach-mode-proxy.js       ← iOS attach mode
│       └── (Android templates built into live-frida-repl.py)
│
├── 📖 Documentation
│   ├── START-HERE.md                  ← 🎯 Primary guide (Android)
│   ├── LIVE-FRIDA-CONNECTION-GUIDE.md ← Complete Android guide
│   ├── LIVE-MANIPULATION-GUIDE.md     ← iOS network manipulation
│   └── FRIDA-CONNECTION-COMPLETE.md   ← Connection status summary
│
├── ⚙️ Configuration
│   ├── config/frida-config.json       ← Network & app settings
│   └── requirements.txt               ← Python dependencies
│
└── 📁 Other
    ├── logs/                          ← Runtime logs
    ├── docs/                          ← Additional documentation
    └── archive/                       ← Historical files
```

---

## 💻 Usage

### Android (Interactive REPL - Recommended)

```bash
# Start REPL - attach to running app
python live-frida-repl.py com.doordash.driverapp

# Start REPL - spawn app fresh
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

### Android (Quick Launchers)
```bash
# Attach to running Dasher app (preserves session)
DASHER-LIVE-MONITOR.bat

# Spawn fresh Dasher instance (clean state)
DASHER-SPAWN-MONITOR.bat
```

### iOS (Legacy)
```bash
# SSH-based launcher (requires 3uTools tunnel)
FRIDA-LIVE-MONITOR-THIS-WORKS.bat

# Manual operations
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning/enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js
python frida-attach.py <PID> frida-interception-and-unpinning/attach-mode-proxy.js
```

### Universal Commands
```bash
# List running apps
python -m frida_tools.ps -Uai

# Find specific app
python -m frida_tools.ps -Uai | grep -i dasher

# Get device info
python -c "import frida; device = frida.get_usb_device(); print(f'Device: {device.name}, ID: {device.id}')"
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

## 📚 Documentation

| Document | Description | When to Read |
|----------|-------------|--------------|
| [`START-HERE.md`](START-HERE.md) | 🎯 Primary guide for Android development | **Start here** |
| [`LIVE-FRIDA-CONNECTION-GUIDE.md`](LIVE-FRIDA-CONNECTION-GUIDE.md) | Complete Android development guide (20KB) | Detailed reference |
| [`LIVE-MANIPULATION-GUIDE.md`](LIVE-MANIPULATION-GUIDE.md) | iOS network manipulation guide | iOS users |
| [`FRIDA-CONNECTION-COMPLETE.md`](FRIDA-CONNECTION-COMPLETE.md) | Connection status summary | Quick overview |
| [`VISUAL-QUICK-GUIDE.md`](VISUAL-QUICK-GUIDE.md) | Visual walkthrough | Visual learners |
| [`cleanup.md`](cleanup.md) | Project organization manifest | Understanding structure |

---

## 🛡️ Security & Ethics

### ⚠️ Authorized Use Only

This framework is designed for:
- ✅ **Security research** on owned devices
- ✅ **App debugging and development**
- ✅ **Network analysis and testing**
- ✅ **Penetration testing with authorization**
- ✅ **Educational purposes**

**NOT for:**
- ❌ Unauthorized access to systems
- ❌ Bypassing security for malicious purposes
- ❌ Production environment attacks without authorization
- ❌ Any illegal activities

### Default Credentials
- iOS default root password: `alpine` (⚠️ **change on production devices!**)
- SSH port (3uTools): `10022`

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 🙏 Acknowledgments

- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [HTTP Toolkit](https://httptoolkit.tech/) - HTTP debugging proxy
- [3uTools](http://www.3u.com/) - iOS device management

---

## 📄 License

This project is intended for security research and educational purposes only. Use responsibly and only on systems you own or have explicit permission to test.

---

**Happy Researching! 🎉**

For detailed usage examples and advanced techniques, see the documentation links above.
