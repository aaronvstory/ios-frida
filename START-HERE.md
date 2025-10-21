# 🚀 START HERE - Frida Live Development

## ✅ **CONNECTION ESTABLISHED!**

**Device Detected:** Pixel 4 (Android)
**Connection:** USB via Frida
**Status:** 🟢 **FULLY OPERATIONAL**

---

## 🎯 What We Discovered

You have a **Pixel 4 Android device** (not iPhone as originally assumed!)

- Device ID: `1AEAFS000010KE`
- Frida connected via USB (no SSH tunnel needed!)
- Two DoorDash apps available:
  - **Dasher** (Driver app) - `com.doordash.driverapp` ← Primary target
  - **DoorDash** (Customer app) - `com.dd.doordash`

---

## 🚀 Quick Start (30 Seconds)

### Option 1: Double-Click Launcher (Easiest!)

```
📁 Double-click this file:
   DASHER-LIVE-MONITOR.bat
```

**What happens:**
1. Connects to Pixel 4 via USB
2. Attaches to running Dasher app
3. Loads complete monitoring script (SSL bypass + Proxy + Network monitoring)
4. Opens interactive REPL where you can type commands!

### Option 2: Spawn Fresh App

```
📁 Double-click this file:
   DASHER-SPAWN-MONITOR.bat
```

**What happens:**
1. Kills any running Dasher app
2. Launches Dasher fresh with Frida
3. Loads complete monitoring from app start
4. Opens interactive REPL

### Option 3: Command Line

```bash
python live-frida-repl.py com.doordash.driverapp
```

---

## 💻 What You Can Do In The REPL

Once the REPL starts, you can type commands:

```
frida> load all          # Load complete script (SSL + Proxy + Monitoring)
frida> load network      # Just network monitoring
frida> load ssl-unpin    # Just SSL bypass
frida> load proxy        # Just proxy config

frida> js console.log("Test!")  # Execute JavaScript code
frida> save my-script.js        # Save current script
frida> run my-script.js         # Load and run script from file
frida> quit                     # Exit
```

---

## 📖 Documentation Files

| File | What It Is | When To Read |
|------|-----------|-------------|
| **FRIDA-CONNECTION-COMPLETE.md** | ✅ **READ THIS FIRST!** | Overview & quick start |
| **LIVE-FRIDA-CONNECTION-GUIDE.md** | Complete technical guide | Detailed usage & examples |
| **LIVE-MANIPULATION-GUIDE.md** | iOS/network manipulation | Reference (iOS focused) |
| **README.md** | Original project docs | Background info |

---

## 🎮 Example REPL Session

```bash
$ DASHER-LIVE-MONITOR.bat

============================================================
   DASHER LIVE MONITOR - Interactive Frida REPL
============================================================

Device: Pixel 4 (Android) via USB
App: DoorDash Dasher (com.doordash.driverapp)

[10:30:12] [SUCCESS] Connected to: Pixel 4 (1AEAFS000010KE)
[10:30:13] [SUCCESS] Attached to com.doordash.driverapp
[10:30:13] [SUCCESS] Script loaded successfully
[10:30:13] [SCRIPT] [*] Complete monitoring script loaded
[10:30:13] [SCRIPT] [+] SSLContext bypassed
[10:30:13] [SCRIPT] [+] Proxy configured: 192.168.50.9:8000
[10:30:13] [SCRIPT] [+] All hooks installed successfully!

Commands:
  load <template>  - Load script template
  js <code>        - Execute JavaScript
  save <file>      - Save current script
  quit             - Exit

frida> js console.log("Testing Dasher app!")
[10:30:45] [SCRIPT] Testing Dasher app!

frida> load network
[10:31:02] [SUCCESS] Script loaded successfully
[10:31:02] [SCRIPT] [*] Network monitoring enabled

# Now use the Dasher app on your phone...
[10:31:15] [SCRIPT] [→] GET https://api.doordash.com/v1/consumer/me
[10:31:16] [SCRIPT] [←] 200 https://api.doordash.com/v1/consumer/me

frida> save my-dasher-monitor.js
[10:32:00] [SUCCESS] Script saved to my-dasher-monitor.js

frida> quit
```

---

## 🎯 Common Tasks

### Task 1: Monitor All Network Traffic

```bash
# 1. Start REPL
DASHER-LIVE-MONITOR.bat

# 2. At the prompt:
frida> load network

# 3. Use Dasher app on your phone
# 4. Watch requests appear in console!
```

### Task 2: Route Traffic to HTTP Toolkit

```bash
# 1. Open HTTP Toolkit at http://192.168.50.9:8000
# 2. Start REPL
DASHER-LIVE-MONITOR.bat

# 3. Load complete script:
frida> load all

# 4. Look for success messages:
[+] Proxy configured: 192.168.50.9:8000
[+] SSLContext bypassed

# 5. Use Dasher app
# 6. Traffic appears in HTTP Toolkit!
```

### Task 3: Develop Custom Script

```bash
# Terminal 1: Start REPL
python live-frida-repl.py com.doordash.driverapp
frida> load all
frida> save base.js

# Terminal 2: Edit script
notepad base.js
# (Make your changes)

# Back to Terminal 1: Reload
frida> run base.js

# Repeat: edit -> run -> test
```

### Task 4: Test Quick JavaScript

```bash
# Start REPL
DASHER-LIVE-MONITOR.bat

# Execute any JavaScript:
frida> js console.log("Android version: " + Java.androidVersion)
[SCRIPT] Android version: 13

frida> js Java.perform(function() { console.log("Java ready!"); })
[SCRIPT] Java ready!
```

---

## 📚 Script Templates Built-In

| Template | What It Does |
|----------|-------------|
| `all` | **Complete monitoring + SSL bypass + Proxy** (USE THIS!) |
| `network` | Monitor all HTTP/HTTPS requests |
| `ssl-unpin` | Bypass SSL certificate pinning |
| `proxy` | Configure HTTP Toolkit proxy |
| `basic` | Minimal test script |

---

## 🔥 HTTP Toolkit Integration

### Complete Workflow

```bash
# STEP 1: Open HTTP Toolkit
# Navigate to: http://192.168.50.9:8000

# STEP 2: Launch Dasher Monitor
DASHER-LIVE-MONITOR.bat

# STEP 3: Verify Success
# Look for these messages:
[+] SSLContext bypassed
[+] Proxy configured: 192.168.50.9:8000
[+] All hooks installed successfully!

# STEP 4: Use Dasher App
# Open Dasher on your Pixel 4
# Make requests (refresh, navigate, etc.)

# STEP 5: Watch Traffic
# HTTP Toolkit shows all decrypted HTTPS traffic!

# STEP 6: Manipulate (Optional)
# In HTTP Toolkit:
# - Click requests to view details
# - Use "Edit & Resend" to modify
# - Set breakpoints on URLs
# - Replay requests with changes
```

---

## 🎓 Learning Path

### Level 1: First Time (5 minutes)

1. Double-click `DASHER-LIVE-MONITOR.bat`
2. Wait for connection messages
3. Type: `frida> js console.log("Hello!")`
4. See the output!

### Level 2: Network Monitoring (15 minutes)

1. Launch REPL
2. Load network template: `frida> load network`
3. Use Dasher app on phone
4. Watch requests appear in console

### Level 3: HTTP Toolkit (30 minutes)

1. Open HTTP Toolkit
2. Launch REPL: `DASHER-LIVE-MONITOR.bat`
3. Load complete script: `frida> load all`
4. Use Dasher app
5. See decrypted traffic in HTTP Toolkit
6. Try modifying requests

### Level 4: Custom Scripts (Ongoing)

1. Read `LIVE-FRIDA-CONNECTION-GUIDE.md`
2. Check example scripts
3. Create your own `.js` file
4. Test: `frida> run my-script.js`
5. Iterate and improve

---

## 🔧 Troubleshooting

### REPL won't connect

**Solution:**
```bash
# Check USB connection
python -m frida_tools.ps -U

# Should list processes
# If not, check USB cable and Android USB debugging
```

### Can't find Dasher app

**Solution:**
```bash
# List all apps
python -m frida_tools.ps -Uai | grep -i dasher

# Expected output:
#   -  Dasher  com.doordash.driverapp

# If not there:
# 1. Make sure Dasher is installed
# 2. Launch Dasher on your phone
# 3. Try again
```

### No traffic in HTTP Toolkit

**Solution:**
```bash
# 1. Verify HTTP Toolkit is at 192.168.50.9:8000
# 2. In REPL, load complete script:
frida> load all

# 3. Look for success messages:
[+] Proxy configured: 192.168.50.9:8000

# 4. Use Dasher app to make requests
# 5. Refresh HTTP Toolkit page
```

### Script errors

**Check JavaScript syntax:**
```javascript
// Bad - missing Java.perform()
console.log(Java.androidVersion);  // ERROR!

// Good - wrapped in Java.perform()
Java.perform(function() {
    console.log(Java.androidVersion);  // Works!
});
```

---

## 📁 Files Overview

```
C:\claude\ios frida\
│
├── 🎯 NEW TOOLS (USE THESE!)
│   ├── DASHER-LIVE-MONITOR.bat              ← Quick launcher (attach mode)
│   ├── DASHER-SPAWN-MONITOR.bat             ← Quick launcher (spawn mode)
│   ├── live-frida-repl.py                   ← Interactive REPL tool
│   ├── FRIDA-CONNECTION-COMPLETE.md         ← Success summary
│   └── LIVE-FRIDA-CONNECTION-GUIDE.md       ← Complete technical guide
│
├── 🔧 ORIGINAL TOOLS (Still useful)
│   ├── FRIDA-LIVE-MONITOR.bat               ← Original SSH-based launcher
│   ├── frida-spawn.py                       ← Core spawn functionality
│   ├── frida-attach.py                      ← Core attach functionality
│   ├── live-network-monitor.py              ← Advanced monitor
│   └── plink.exe                            ← SSH tunnel utility
│
├── 📖 DOCUMENTATION
│   ├── START-HERE-NEW.md                    ← This file!
│   ├── FRIDA-CONNECTION-COMPLETE.md         ← Quick start guide
│   ├── LIVE-FRIDA-CONNECTION-GUIDE.md       ← Complete guide
│   ├── LIVE-MANIPULATION-GUIDE.md           ← iOS reference
│   ├── README.md                            ← Original docs
│   └── ... (other guides)
│
├── 📁 config/
│   └── frida-config.json                    ← Network settings
│
└── 📁 frida-interception-and-unpinning/
    └── ... (iOS Frida scripts)
```

---

## ✅ What Works Now

- ✅ **USB Connection** - Direct Frida over USB (no SSH needed!)
- ✅ **Device Detection** - Pixel 4 Android recognized
- ✅ **App Attachment** - Can attach to Dasher & DoorDash apps
- ✅ **App Spawning** - Can launch apps fresh with Frida
- ✅ **Interactive REPL** - Live script development environment
- ✅ **Script Templates** - 5 ready-to-use templates
- ✅ **Network Monitoring** - See all HTTP/HTTPS requests
- ✅ **SSL Unpinning** - Bypass certificate pinning
- ✅ **Proxy Config** - Route to HTTP Toolkit
- ✅ **Live JavaScript** - Execute code in real-time
- ✅ **Save/Load Scripts** - Persistent script development

---

## 🚀 Ready to Start?

### Recommended First Steps:

1. **Read:** `FRIDA-CONNECTION-COMPLETE.md` (5 min overview)
2. **Launch:** `DASHER-LIVE-MONITOR.bat` (connects to Dasher)
3. **Test:** Type `frida> js console.log("I'm in!")`
4. **Experiment:** Try `frida> load network` and use the app
5. **Learn:** Read `LIVE-FRIDA-CONNECTION-GUIDE.md` for advanced usage

### For HTTP Toolkit:

1. **Open:** HTTP Toolkit at `http://192.168.50.9:8000`
2. **Launch:** `DASHER-LIVE-MONITOR.bat`
3. **Load:** `frida> load all`
4. **Verify:** Look for `[+] Proxy configured: 192.168.50.9:8000`
5. **Use:** Open Dasher app on phone and watch traffic!

---

## 🎉 You're All Set!

Everything is configured and ready to go. Just double-click `DASHER-LIVE-MONITOR.bat` to start developing Frida scripts live!

**Happy Hacking! 🚀**
