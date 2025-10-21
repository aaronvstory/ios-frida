# 🚀 START HERE - Frida Live Monitor

## The Problem You Had

```
❌ HTTP Toolkit Error:
"Failed to intercept com.doordash.dasher: Proxy IP detection on target device
 failed for port 8000 and IPs ["192.168.50.141 (unreachable-from"]"
```

## The Solution We Built

✅ **Direct Frida injection via 3uTools SSH tunnel**
✅ **Bypasses HTTP Toolkit's proxy detection**
✅ **Captures all HTTPS traffic**
✅ **Live network observation and manipulation**

---

## Quick Start (30 Seconds)

### Step 1: Verify SSH Tunnel
You already opened it via 3uTools:
```
Open SSH Tunnel ✓
Succeeded to open SSH tunnel.
IP: 127.0.0.1
```

### Step 2: Run the Launcher
```bash
FRIDA-LIVE-MONITOR.bat
```

### Step 3: Choose Mode
- **Option 1: SPAWN** (recommended) - App restarts, most reliable
- **Option 2: ATTACH** - App stays open, preserves login

### Step 4: Done!
Traffic appears in HTTP Toolkit at `http://192.168.50.9:8000`

---

## What This Does

```
┌─────────────┐
│  3uTools    │ SSH Tunnel
│  127.0.0.1  │─────────┐
└─────────────┘         │
                        ▼
┌─────────────┐    ┌──────────┐     ┌──────────────┐
│   Frida     │───▶│  iPhone  │────▶│ HTTP Toolkit │
│   Script    │    │  Dasher  │     │ 192.168.50.9 │
└─────────────┘    └──────────┘     └──────────────┘
     ▲                  │
     │                  │
     └──────────────────┘
   Inject Proxy Config
   + SSL Bypass
```

**Flow:**
1. Frida connects via SSH tunnel (3uTools)
2. Injects proxy config into Dasher app memory
3. Bypasses SSL pinning
4. Routes all traffic to HTTP Toolkit
5. You see and manipulate everything!

---

## Key Files (Only 3 You Need)

### 1️⃣ **FRIDA-LIVE-MONITOR.bat** ← RUN THIS
Main launcher with automatic setup

### 2️⃣ **LIVE-MANIPULATION-GUIDE.md** ← READ THIS
Complete guide for observing and manipulating traffic

### 3️⃣ **live-network-monitor.py** ← OPTIONAL
Advanced monitoring with logging
```bash
python live-network-monitor.py com.doordash.dasher
```

---

## What You Can Do Now

### 🔍 **Observe**
- See all API calls in real-time
- View request/response headers and bodies
- Track authentication tokens
- Monitor network performance

### 🛠️ **Manipulate**
- Modify request headers (User-Agent, etc.)
- Change POST data before sending
- Block analytics/tracking requests
- Inject custom parameters
- Replay requests with changes

### 🐛 **Debug**
- Understand authentication flow
- Test different payloads
- Identify API endpoints
- Analyze app behavior

---

## Common Commands

### Basic (Use the .bat file!)
```bash
FRIDA-LIVE-MONITOR.bat
```

### Advanced Python Monitor
```bash
# Basic usage
python live-network-monitor.py com.doordash.dasher

# Attach to running app (PID 1234)
python live-network-monitor.py com.doordash.dasher --attach 1234

# Custom log file
python live-network-monitor.py com.doordash.dasher --log-file my-traffic.log
```

### Manual Operations
```bash
# Spawn mode
python frida-spawn.py com.doordash.dasher frida-interception-and-unpinning\enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js

# Attach mode
python frida-attach.py [PID] frida-interception-and-unpinning\attach-mode-proxy.js

# Find app PID
frida-ps -Uai | findstr "dasher"
```

---

## Troubleshooting

### No traffic in HTTP Toolkit?

**Checklist:**
- ✅ HTTP Toolkit running at `192.168.50.9:8000`
- ✅ Console shows "Proxy configured: 192.168.50.9:8000"
- ✅ Console shows "Bypassing SSL pinning..."
- ✅ App is making network requests (try refreshing)

**Quick fix:**
```bash
# Try spawn mode (option 1)
FRIDA-LIVE-MONITOR.bat
# Choose: 1
```

### SSH connection failed?

**Solution:**
```bash
# Re-open in 3uTools
# Look for: "Succeeded to open SSH tunnel"
```

### App not found (attach mode)?

**Solution:**
```bash
# Make sure Dasher app is running first
frida-ps -Uai | findstr "dasher"
```

---

## Project Structure (After Cleanup)

```
📦 C:\claude\ios frida\
│
├── 🎯 FRIDA-LIVE-MONITOR.bat          ← START HERE!
├── 📖 LIVE-MANIPULATION-GUIDE.md      ← COMPLETE GUIDE
├── 📄 START-HERE.md                   ← THIS FILE
├── 📄 README.md                       ← Overview
│
├── 🐍 Core Python Files
│   ├── live-network-monitor.py        ← Advanced monitor
│   ├── frida-spawn.py                 ← Spawn mode
│   └── frida-attach.py                ← Attach mode
│
├── 📁 config/
│   └── frida-config.json              ← Settings
│
├── 📁 frida-interception-and-unpinning/
│   ├── enhanced-...-fixed.js          ← Best spawn script
│   ├── attach-mode-proxy.js           ← Best attach script
│   └── ... (other scripts)
│
├── 📁 logs/                           ← Your logs
├── 📁 archive/                        ← Old files (69 archived)
│   ├── old-launchers/
│   ├── old-scripts/
│   └── old-docs/
│
└── 🔧 Other Files
    ├── plink.exe                      ← SSH tunnel
    ├── requirements.txt               ← Python deps
    └── ... (docs & guides)
```

**Before cleanup:** 52 files in root 😵
**After cleanup:** 15 essential files ✨

---

## Next Steps

### For First-Time Use
1. ✅ Run `FRIDA-LIVE-MONITOR.bat`
2. ✅ Choose SPAWN mode (option 1)
3. ✅ Watch traffic in HTTP Toolkit
4. ✅ Read `LIVE-MANIPULATION-GUIDE.md`

### For Advanced Usage
1. ✅ Learn Frida hooks from the guide
2. ✅ Use `live-network-monitor.py` for logging
3. ✅ Modify scripts for custom behavior
4. ✅ Set breakpoints in HTTP Toolkit

### For Understanding
1. ✅ Read `LIVE-MANIPULATION-GUIDE.md` (comprehensive)
2. ✅ Check `README.md` (overview)
3. ✅ Review `WORKSPACE-CLEANUP-SUMMARY.md` (what changed)

---

## Why This Works

### The Old Approach (HTTP Toolkit alone)
```
HTTP Toolkit tries to configure iOS proxy
         ↓
iOS detects configuration attempt
         ↓
Security/jailbreak detection blocks it
         ↓
❌ "Proxy IP detection failed"
```

### Our New Approach (Frida injection)
```
3uTools creates SSH tunnel to iPhone
         ↓
Frida connects via SSH (bypasses detection)
         ↓
Inject proxy config into app memory directly
         ↓
App never knows proxy was externally configured
         ↓
✅ All traffic flows to HTTP Toolkit
```

---

## Documentation Guide

| File | Purpose | When to Read |
|------|---------|--------------|
| **START-HERE.md** | This file - Quick overview | First time |
| **README.md** | Project overview and commands | Reference |
| **LIVE-MANIPULATION-GUIDE.md** | Complete usage guide | Before advanced use |
| **QUICK-START.md** | Fast setup reference | Quick lookup |
| **WORKSPACE-CLEANUP-SUMMARY.md** | What changed in cleanup | Understanding changes |
| **CLEANUP-PLAN.md** | Organization details | If curious |

---

## Success Indicators

When everything works, you'll see:

**Console Output:**
```
[+] Connected to device: iPhone
[+] Spawning com.doordash.dasher...
[*] Configuring proxy for defaultSessionConfiguration
[+] Proxy configured: 192.168.50.9:8000
[*] Bypassing SSL pinning in NSURLSession
[*] Bypassing SecTrustEvaluate
[+] Script loaded successfully
```

**HTTP Toolkit:**
- Shows "Intercepted" status
- Displays incoming requests
- Can view/modify traffic

---

## Support & Resources

### Quick Help
```bash
# Test SSH connection
plink.exe -P 10022 root@127.0.0.1 -pw alpine "echo Connected"

# Check Frida server
plink.exe -P 10022 root@127.0.0.1 -pw alpine "ps aux | grep frida-server"

# Start Frida server
plink.exe -P 10022 root@127.0.0.1 -pw alpine "/usr/sbin/frida-server &"
```

### Documentation
- **LIVE-MANIPULATION-GUIDE.md** - Advanced techniques
- **README.md** - Command reference
- **QUICK-START.md** - Setup guide

### Logs
Check `logs/` directory for detailed output

---

## What Changed (Summary)

### Created
- ✅ `FRIDA-LIVE-MONITOR.bat` - Unified launcher
- ✅ `live-network-monitor.py` - Advanced monitor
- ✅ `LIVE-MANIPULATION-GUIDE.md` - Complete guide
- ✅ Updated `README.md` - New overview
- ✅ This file (`START-HERE.md`)

### Organized
- ✅ Archived 69 old files to `archive/`
- ✅ Cleaned root from 52 to 15 files
- ✅ Clear project structure

### Result
- ✅ One main launcher
- ✅ One comprehensive guide
- ✅ Clean workspace
- ✅ HTTP Toolkit proxy bypass working

---

## Ready to Start?

### Run This Now:
```bash
FRIDA-LIVE-MONITOR.bat
```

### Watch This:
```
HTTP Toolkit at: http://192.168.50.9:8000
```

### Read This Next:
```
LIVE-MANIPULATION-GUIDE.md
```

---

**You're all set! Happy monitoring! 🎉**
