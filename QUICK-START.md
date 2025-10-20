# FridaInterceptor - Quick Start Guide

## 🚀 One-Click Launch

```batch
.\start-frida-interceptor.bat
```

That's it! This single command launches the complete FridaInterceptor with iOS version bypass capabilities.

## 📱 Fix DoorDash on iOS 16 Devices

### Problem:
DoorDash Dasher blocks iOS 16.x devices

### Solution (30 seconds):
1. Run `.\start-frida-interceptor.bat`
2. Press **[V]** - Select iOS version
3. Choose **[3]** - iOS 17.6.1 (recommended)
4. Press **[4]** - Attach to DasherApp (stay logged in)
5. ✅ DoorDash now works!

## 🎯 Main Features

- **iOS Version Spoofing** - Bypass app version checks
- **SSL Pinning Bypass** - Capture HTTPS traffic
- **HTTP Toolkit Integration** - View all app traffic
- **Stay Logged In** - Attach mode preserves session
- **Multiple Apps** - DoorDash, Uber, Lyft support

## 📁 Clean Directory Structure

```
C:\claude\ios frida\
│
├── start-frida-interceptor.bat   # ← MAIN LAUNCHER (use this)
├── FridaInterceptor.ps1          # Main PowerShell script
├── frida-attach.py               # Python helper for attach mode
├── frida-spawn.py                # Python helper for spawn mode
│
├── config/                       # Configuration files
│   ├── frida-config.json        # Network & app settings
│   └── ios-versions.json        # iOS version database
│
├── frida-interception-and-unpinning/  # JavaScript injection scripts
│   ├── ios-version-bypass-template.js # Dynamic iOS bypass
│   └── *.js                          # Various bypass scripts
│
└── logs/                         # Runtime logs
```

## ⚙️ Prerequisites

- iPhone with Frida installed
- USB connection to iPhone
- HTTP Toolkit running on port 8000
- Python with frida-tools installed

## 🔧 Menu Options

When you run the launcher, you'll see:

```
[V] Select iOS Version    - Choose version to spoof
[1-3] Spawn Mode         - Restart app (logs out)
[4-6] Attach Mode        - Keep logged in
[L] List Running Apps    - See available processes
[T] Test Connection      - Verify Frida setup
```

## 💡 Tips

- **DoorDash Fix**: Always use iOS 17.6.1 or higher
- **Stay Logged In**: Use attach mode (options 4-6)
- **Fresh Start**: Use spawn mode (options 1-3)
- **Check Proxy**: Ensure HTTP Toolkit is running

## 🆘 Troubleshooting

If DoorDash still doesn't work:
1. Make sure you selected iOS 17+ in the [V] menu
2. Verify the bypass shows "ENABLED" at top of menu
3. Try spawn mode [1] for complete control
4. Check HTTP Toolkit is receiving traffic

## 📝 Single Entry Point

**There is only ONE main application now:**
- Launcher: `start-frida-interceptor.bat`
- Script: `FridaInterceptor.ps1`
- Everything else is supporting files

All test files and duplicates have been archived to keep the directory clean.

---
*Directory cleaned and organized on 2025-09-19*