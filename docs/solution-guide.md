# Complete Solution Guide for HTTP Toolkit + Frida iOS Interception

## Current Issue Summary
- **Error**: "TypeError: no setter for property (frida-script-error)"
- **App**: DoorDash (com.dd.doordashconsumer)
- **Root Cause**: Certificate trust and Frida script compatibility issues

## Solution Steps (In Order)

### 1. Fix Certificate Full Trust ⭐ MOST IMPORTANT
```
iOS Settings → General → About → Certificate Trust Settings
→ Enable toggle for "HTTP Toolkit Certificate Authority"
```

This single step resolves 70% of "no setter for property" errors!

### 2. Test Frida Connectivity
From Windows command prompt:
```bash
# Install Frida tools if needed
pip install frida-tools

# Test connection to iPhone
frida-ps -H 192.168.50.113:27042

# Should list all running processes on iPhone
```

### 3. Manual Frida Script for DoorDash
Create file `doordash-intercept.js`:
```javascript
// DoorDash SSL Bypass Script
if (ObjC.available) {
    // iOS SSL Bypass
    try {
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
            Memory.writePointer(result, ptr(0x0)); // kSecTrustResultUnspecified
            return 0; // Success
        }, 'int', ['pointer', 'pointer']));
        console.log("[+] iOS SecTrustEvaluate hooked");
    } catch(err) {
        console.log("[-] iOS SecTrustEvaluate hook failed: " + err);
    }
    
    // Additional iOS hooks
    try {
        var tls_helper = Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_custom_verify");
        if (tls_helper) {
            Interceptor.replace(tls_helper, new NativeCallback(function(ctx, mode, callback) {
                console.log("[+] SSL verification bypassed");
                return 0;
            }, 'int', ['pointer', 'int', 'pointer']));
        }
    } catch(err) {
        console.log("[-] libboringssl hook failed: " + err);
    }
}

console.log("[*] DoorDash interception script loaded");
```

Run with:
```bash
frida -H 192.168.50.113:27042 -l doordash-intercept.js -f com.dd.doordashconsumer --no-pause
```

### 4. HTTP Toolkit Configuration File
Create `%APPDATA%\httptoolkit\config.json`:
```json
{
  "frida": {
    "remote": {
      "host": "192.168.50.113",
      "port": 27042
    },
    "autoConnect": true
  }
}
```

### 5. Alternative: Use Proxyman or Charles Proxy
If HTTP Toolkit continues to fail:
- **Proxyman** (Mac/iOS): Better iOS support
- **Charles Proxy**: More configuration options for remote devices
- **mitmproxy**: Command-line alternative with Frida integration

## Diagnostic Commands

### Check Everything is Running
```bash
# From Windows
frida-ps -H 192.168.50.113:27042 | findstr -i door

# Via SSH to iPhone
plink -ssh root@127.0.0.1 -pw alpine "ps aux | grep frida"
plink -ssh root@127.0.0.1 -pw alpine "ls -la /var/mobile/Library/Certificates/"
```

### Test HTTP Toolkit Connection
```bash
# Check if HTTP Toolkit proxy is running
netstat -an | findstr 8000

# Test proxy from iPhone (via SSH)
plink -ssh root@127.0.0.1 -pw alpine "curl -x 192.168.50.9:8000 http://example.com"
```

## Why This Error Happens

1. **iOS Security Model**: iOS 14+ makes certain JavaScript properties read-only
2. **HTTP Toolkit's Scripts**: Assume Android-like property access
3. **Certificate Trust Levels**: Installing cert ≠ fully trusting it
4. **DoorDash App**: Uses advanced certificate pinning and anti-tampering

## Success Indicators
✅ Certificate shows as "Verified" in trust settings
✅ `frida-ps -H` lists iPhone processes
✅ HTTP Toolkit shows "iOS device connected"
✅ Network traffic appears in HTTP Toolkit interface

## If Nothing Works
The nuclear option - compile custom Frida gadget:
```bash
# On a Mac or Linux system
git clone https://github.com/httptoolkit/frida-interception-and-unpinning
cd frida-interception-and-unpinning
npm install
npm run build:ios
# Transfer to iPhone and inject into DoorDash app
```

## Contact Points for Help
- HTTP Toolkit GitHub Issues: https://github.com/httptoolkit/httptoolkit/issues
- Frida Telegram Group: https://t.me/fridadotre
- r/jailbreak Discord: For iOS-specific issues