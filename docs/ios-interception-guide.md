# iOS HTTP Interception Manual Setup Guide

## Prerequisites
- Install HTTP Toolkit on computer
- iOS device on same WiFi network as computer
- Jailbroken device (for Frida support)

## Step 1: Proxy Configuration
1. Open iOS Settings → WiFi
2. Select your network → Configure Proxy
3. Set to **Manual**
4. Enter:
   - **Server**: Your computer's IP (e.g., `192.168.50.9`)
   - **Port**: HTTP Toolkit proxy port (default `8000`)
5. Save settings

## Step 2: Certificate Installation
1. Visit `http://amiusing.httptoolkit.tech/certificate` on iOS device
   - Or scan the QR code from HTTP Toolkit
2. Download the CA certificate
3. Go to Settings → General → Profile
4. Install "HTTP Toolkit CA" certificate
5. **IMPORTANT**: Go to Settings → General → About → Certificate Trust Settings
6. Enable **"Full Trust"** for HTTP Toolkit Certificate Authority

## Step 3: Verification
1. Visit `https://amiusing.httptoolkit.tech`
2. Should see "HTTP Toolkit is intercepting this connection"
3. If not working, check:
   - Proxy settings are correct
   - Certificate is fully trusted
   - Both devices on same network

## For Jailbroken Devices with Frida

### Additional Setup
1. Install Frida from Cydia/Sileo
2. Ensure Frida server is running:
```bash
# SSH to device
ssh root@[device-ip]
# Start Frida
frida-server -l 0.0.0.0:27042 &
```

### Certificate Location
- Manual installation path: `/var/mobile/Library/Certificates/`
- Ensure proper permissions:
```bash
chown mobile:mobile /var/mobile/Library/Certificates/http-toolkit-ca-certificate.crt
chmod 644 /var/mobile/Library/Certificates/http-toolkit-ca-certificate.crt
```

### Restart Trust Services
```bash
killall -9 trustd
killall -9 securityd
```

## Troubleshooting
- **"No setter for property" error**: Certificate not fully trusted
- **Connection refused**: Check firewall on computer
- **No interception**: Verify proxy settings and certificate trust
- **Apps still using HTTPS**: May need Frida scripts for certificate pinning bypass

## To Disable
1. Remove proxy configuration from WiFi settings
2. Optionally remove certificate from Settings → General → Profile

## Notes
- CA certificate is unique to your HTTP Toolkit installation
- Fully automated setup not yet available (manual process required)
- Some apps may require additional Frida scripts for pinning bypass