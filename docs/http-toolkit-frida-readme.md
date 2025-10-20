# HTTP Toolkit Frida Mobile Interception Scripts

## Purpose
This repo contains Frida scripts designed to do everything required for fully automated HTTPS MitM interception on mobile devices.

## Key Capabilities
- Redirect traffic to HTTP(S) proxy
- Inject CA certificates into system trust stores
- Patch certificate pinning techniques
- Disable root/jailbreak detection
- Block HTTP/3 connections

## iOS Setup Steps

### Prerequisites
1. Jailbroken iOS device
2. Frida installed via Cydia/Sileo
3. HTTP Toolkit running on computer

### Configuration Steps

1. **Configure proxy details in `config.js`**:
```javascript
// Example config.js
module.exports = {
    proxy: {
        host: '192.168.50.9',  // Your Windows PC IP
        port: 8000             // HTTP Toolkit proxy port
    }
};
```

2. **Find target app ID**:
```bash
frida-ps -Uai
# or for specific app
frida-ps -Uai | grep -i doordash
```

3. **Run Frida with iOS-specific scripts**:
```bash
frida -U \
 -l ./config.js \
 -l ./native-connect-hook.js \
 -l ./ios/ios-proxy-override.js \
 -l ./ios/ios-disable-pinning.js \
 -f com.dd.doordashconsumer
```

## Notable Scripts
- **`native-connect-hook.js`**: Captures all network traffic at the native level
- **`native-tls-hook.js`**: Modifies TLS validation to accept custom certificates
- **`ios/ios-proxy-override.js`**: Forces iOS apps to use configured proxy
- **`ios/ios-disable-pinning.js`**: Bypasses certificate pinning

## Android Setup (for reference)
```bash
frida -U \
 -l ./config.js \
 -l ./native-connect-hook.js \
 -l ./android/android-proxy-override.js \
 -f $PACKAGE_ID
```

## Important Notes
- Funding: Supported by NLnet's NGI Zero Entrust Fund
- Recommended for security testing and research purposes only
- Ensure you have permission to test the target application