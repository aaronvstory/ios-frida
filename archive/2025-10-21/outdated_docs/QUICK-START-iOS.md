# iOS Frida Quick Start - 30 Second Setup

**For full details, see:** `docs/IOS-FRIDA-CONNECTION-GUIDE.md`

---

## Working Setup (As of Oct 8, 2025)

- **Device:** iPhone SE2, iOS 16.3.1 (Jailbroken - Dopamine RootHide)
- **IP:** 192.168.50.130
- **Method:** USB (RECOMMENDED)
- **frida-server Status:** Running (PID 921)

---

## ⚡ Quick Launch (3 Steps)

### 1. Connect iPhone via USB

```bash
# Verify connection
python -c "import frida; print(frida.get_usb_device())"
```

Expected: `Device: Apple iPhone, ID: 00008030-001229C01146402E`

### 2. Launch Dasher with Frida

```bash
python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/dasher-api-interceptor.js"
```

### 3. Verify Success

You should see:
```
[+] Connected to device: Apple iPhone
[+] Spawning com.doordash.dasher...
[+] SSL Pinning bypass hooks installed
[+] Proxy routing configured
[+] All hooks installed successfully
```

---

## 🔧 If Something Fails

### Device Not Found?

```bash
# Check USB connection
python -c "import frida; print(frida.enumerate_devices())"

# Reconnect USB cable
# Trust computer on iPhone
```

### frida-server Not Running?

On iPhone (via 3uTools SSH or terminal):
```bash
su                      # Password: alpine
frida-server &          # Start in background
ps aux | grep frida     # Verify running
```

### White Screen in App?

The `dasher-api-interceptor.js` script fixes this by intercepting the `/v3/dasher/me/` 404 error.

---

## 📱 App Modes

### Spawn Mode (Recommended)
- Restarts app (logs you out)
- 100% reliable proxy routing
- Clean state

```bash
python frida-spawn.py com.doordash.dasher "script.js"
```

### Attach Mode (Preserves Login)
- Keeps session alive
- Need to find PID first

```bash
# Get PID
python -m frida_tools.ps -Uai | grep dasher

# Attach
python frida-attach.py <PID> "script.js"
```

---

## 🎯 Available Scripts

| Script | Purpose |
|--------|---------|
| `enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js` | SSL bypass + HTTP Toolkit proxy |
| `dasher-api-interceptor.js` | **Fixes white screen** + SSL bypass + proxy + logs requests |
| `attach-mode-proxy.js` | For attach mode, optimized for running apps |

---

## 🌐 HTTP Toolkit

1. **Start HTTP Toolkit:** `http://192.168.50.9:8000`
2. **Run Frida script** (includes proxy config)
3. **Use Dasher app**
4. **See decrypted traffic** in HTTP Toolkit

---

## 🚨 Troubleshooting One-Liners

```bash
# Check devices
python -c "import frida; [print(f'{d.name} ({d.type})') for d in frida.enumerate_devices()]"

# List iOS apps
python -m frida_tools.ps -Uai

# Check frida-server on iPhone
ssh root@192.168.50.130 "ps aux | grep frida"  # Password: alpine
```

---

## 📖 For More Details

See **`docs/IOS-FRIDA-CONNECTION-GUIDE.md`** for:
- Complete SSH tunnel setup (if wireless needed)
- plink.exe configuration
- Network connection troubleshooting
- All error messages and solutions
- Configuration file updates

---

## ✅ Current Working Command

```bash
python frida-spawn.py com.doordash.dasher "frida-interception-and-unpinning/dasher-api-interceptor.js"
```

That's it! USB connection just works without any SSH or network complexity.
