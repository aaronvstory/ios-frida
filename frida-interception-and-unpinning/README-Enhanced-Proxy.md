# Enhanced iOS Frida Proxy Interception

This directory contains enhanced Frida scripts for comprehensive iOS network traffic interception and SSL pinning bypass.

## Files

- `enhanced-universal-ssl-pinning-bypass-with-proxy.js` - Main enhanced script with comprehensive network hooks
- `proxy-diagnostics.js` - Diagnostic script to test proxy connectivity
- `universal-ssl-pinning-bypass-with-proxy.js` - Original script (kept for reference)

## Key Improvements in Enhanced Script

### 1. Comprehensive Network API Coverage
- **NSURLSession** - All configuration types (default, ephemeral, background)
- **NSURLRequest** - Both mutable and immutable requests
- **CFNetwork** - Low-level network APIs that bypass NSURLSession
- **Multiple init methods** - Ensures proxy is set regardless of how sessions are created

### 2. Enhanced Proxy Configuration
- HTTP, HTTPS, SOCKS, and FTP proxy settings
- Prevents proxy auto-config override
- Forces all connection types through proxy
- Better error handling and logging

### 3. Stronger SSL Pinning Bypass
- **Security Framework** - SecTrustEvaluate, SecTrustEvaluateWithError
- **AFNetworking** - Complete bypass of all security policies
- **TrustKit** - Popular SSL pinning library bypass
- **Alamofire** - Swift networking library support
- **NSURLSession delegates** - Proper authentication challenge handling

### 4. Debug Logging
- Request counting and URL logging
- Proxy configuration confirmation
- SSL bypass confirmation
- Periodic status reports every 30 seconds
- Framework detection (React Native, Flutter, etc.)

## Usage

### 1. Update Proxy Settings
Edit the proxy configuration in the enhanced script:
```javascript
var proxyHost = "192.168.50.9";  // Your HTTP Toolkit IP
var proxyPort = 8000;            // Your HTTP Toolkit port
```

### 2. Run the Enhanced Script
```bash
# Attach to running app
frida -U -p [PID] -l enhanced-universal-ssl-pinning-bypass-with-proxy.js

# Or spawn new app instance
frida -U -f [bundle-id] -l enhanced-universal-ssl-pinning-bypass-with-proxy.js
```

### 3. Run Diagnostics (if issues occur)
```bash
frida -U -p [PID] -l proxy-diagnostics.js
```

## Expected Output

When working correctly, you should see:
```
[*] Starting Enhanced Universal SSL Pinning Bypass with Proxy...
[*] Target proxy: 192.168.50.9:8000
[*] Objective-C runtime available, installing hooks...
[*] Configuring proxy for defaultSessionConfiguration
[+] Enhanced proxy configured for defaultSessionConfiguration: 192.168.50.9:8000
[*] Installing SSL pinning bypass hooks...
[*] AFNetworking detected, installing bypasses...
[+] Enhanced SSL Pinning bypass hooks installed
[+] Comprehensive proxy routing configured
[+] Network request logging enabled
[+] Ready to intercept ALL traffic!
[*] Script fully loaded and active
[1] NSURLRequest created for: https://api.example.com/data
[*] SecTrustEvaluate bypassed
[*] AFNetworking: Forced setAllowInvalidCertificates = true
```

## Troubleshooting

### Problem: HTTP Toolkit shows no traffic

**Possible Causes:**
1. **Proxy IP/Port mismatch** - Verify HTTP Toolkit is listening on the configured IP:port
2. **Network isolation** - Ensure the iOS device can reach the proxy host
3. **App using custom networking** - Some apps use low-level network APIs
4. **Certificate issues** - HTTP Toolkit certificate may not be trusted

**Solutions:**
1. **Check HTTP Toolkit settings:**
   - Verify it's listening on the correct interface (not just localhost)
   - Check if it's using the expected port (8000)
   - Ensure it's running in iOS proxy mode

2. **Test network connectivity:**
   ```bash
   # From iOS device, test if proxy is reachable
   curl -x http://192.168.50.9:8000 http://httpbin.org/ip
   ```

3. **Run the diagnostic script:**
   ```bash
   frida -U -p [PID] -l proxy-diagnostics.js
   ```

4. **Check iOS certificate trust:**
   - Install HTTP Toolkit certificate in iOS Settings > General > About > Certificate Trust Settings
   - Enable full trust for root certificates

### Problem: App crashes or doesn't work

**Possible Causes:**
1. **Aggressive hooking** - Some apps detect Frida hooks
2. **Missing framework methods** - App uses networking APIs we haven't hooked
3. **Anti-debugging measures** - App has Frida detection

**Solutions:**
1. **Start with original script** - Use the original script first to see if it works
2. **Selective hooking** - Comment out some hooks to identify problematic ones
3. **Check app logs** - Look for crash logs or error messages

### Problem: SSL certificate errors

**Causes:**
- HTTP Toolkit certificate not properly installed/trusted on iOS
- App doing certificate pinning we haven't bypassed

**Solutions:**
1. **Install HTTP Toolkit certificate:**
   - Settings > Wi-Fi > Configure Proxy > Manual
   - Install certificate when prompted
   - Settings > General > About > Certificate Trust Settings > Enable full trust

2. **Check for additional pinning libraries:**
   - Some apps use custom or newer pinning libraries
   - Add additional hooks as needed

## Advanced Configuration

### Custom Networking Libraries
If the app uses custom networking (like Unity, Unreal, or proprietary solutions), you may need to add additional hooks. Look for:

1. **libcurl** - `curl_easy_perform`, `curl_easy_setopt`
2. **OpenSSL** - `SSL_connect`, `SSL_set_verify`
3. **Custom TLS libraries** - App-specific implementations

### Multi-Proxy Setup
For complex setups, you can configure different proxies for different protocols:

```javascript
// HTTP through one proxy
proxyDict.setObject_forKey_("proxy1.example.com", "HTTPProxy");
proxyDict.setObject_forKey_(8080, "HTTPPort");

// HTTPS through another proxy  
proxyDict.setObject_forKey_("proxy2.example.com", "HTTPSProxy");
proxyDict.setObject_forKey_(8443, "HTTPSPort");
```

## Logging and Monitoring

The enhanced script provides detailed logging:
- **Request counting** - Track number of intercepted requests
- **URL logging** - See what endpoints the app is calling
- **SSL bypass confirmation** - Confirm when certificates are bypassed
- **Framework detection** - Know what networking libraries the app uses
- **Periodic status** - Get updates every 30 seconds

## Security Notes

- These scripts disable SSL certificate validation - only use on apps you own or have permission to test
- Traffic will be visible in plain text through HTTP Toolkit
- Some apps may detect these modifications and refuse to work
- Always test in a controlled environment

## Support

If you encounter issues:
1. Check the console output for error messages
2. Run the diagnostic script to test basic functionality
3. Verify HTTP Toolkit is properly configured and accessible
4. Test with a simple app first (like Safari) to confirm setup