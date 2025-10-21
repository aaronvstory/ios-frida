/**
 * DoorDash Complete Bypass - iOS Version + SSL Pinning + Proxy
 * Combines all necessary bypasses for older iOS devices
 */

console.log("[+] DoorDash Complete Bypass Loading...");
console.log("[+] Includes: iOS Version Spoofing + SSL Bypass + Proxy Routing");

// Configuration
const PROXY_HOST = "192.168.50.9";
const PROXY_PORT = 8000;
const SPOOFED_IOS = "18.0";

// ============= iOS VERSION BYPASS =============
if (ObjC.available) {
    console.log("[+] Installing iOS version hooks...");

    // Hook UIDevice systemVersion
    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function (retval) {
                retval.replace(ObjC.classes.NSString.stringWithString_(SPOOFED_IOS));
                console.log("[+] UIDevice.systemVersion -> " + SPOOFED_IOS);
            }
        });
    } catch (e) {}

    // Hook NSProcessInfo
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;

        // operatingSystemVersion
        Interceptor.attach(NSProcessInfo['- operatingSystemVersion'].implementation, {
            onLeave: function (retval) {
                var versionPtr = new NativePointer(retval);
                versionPtr.writeU64(18);
                versionPtr.add(8).writeU64(0);
                versionPtr.add(16).writeU64(0);
            }
        });

        // isOperatingSystemAtLeastVersion
        Interceptor.attach(NSProcessInfo['- isOperatingSystemAtLeastVersion:'].implementation, {
            onLeave: function (retval) {
                retval.replace(ptr(0x1)); // Always YES
            }
        });
    } catch (e) {}

    // Hook User-Agent modifications
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

        Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'].implementation, {
            onEnter: function (args) {
                var field = new ObjC.Object(args[3]).toString();
                if (field.toLowerCase() === "user-agent") {
                    var value = new ObjC.Object(args[2]).toString();
                    var newUA = value.replace(/iOS 16\.\d+(\.\d+)?/, "iOS " + SPOOFED_IOS);
                    newUA = newUA.replace(/CFNetwork\/1404\.\d+(\.\d+)?/, "CFNetwork/1490.0.4");
                    newUA = newUA.replace(/Darwin\/22\.\d+(\.\d+)?/, "Darwin/24.0.0");

                    if (newUA !== value) {
                        args[2] = ObjC.classes.NSString.stringWithString_(newUA);
                        console.log("[+] User-Agent updated to iOS " + SPOOFED_IOS);
                    }
                }
            }
        });
    } catch (e) {}

    console.log("[+] iOS version bypass installed");
}

// ============= SSL PINNING BYPASS =============
console.log("[+] Installing SSL pinning bypass...");

// NSURLSession SSL bypass
if (ObjC.available) {
    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration'].forEach(function(method) {
            var original = NSURLSessionConfiguration[method];
            if (original) {
                NSURLSessionConfiguration[method] = function() {
                    var config = original.call(this);
                    config.setConnectionProxyDictionary_({
                        "HTTPEnable": 1,
                        "HTTPProxy": PROXY_HOST,
                        "HTTPPort": PROXY_PORT,
                        "HTTPSEnable": 1,
                        "HTTPSProxy": PROXY_HOST,
                        "HTTPSPort": PROXY_PORT
                    });
                    console.log("[+] Proxy configured in NSURLSessionConfiguration");
                    return config;
                };
            }
        });

        // Disable certificate validation
        Interceptor.attach(NSURLSessionConfiguration['- setURLCache:'].implementation, {
            onEnter: function(args) {
                // Use this hook point to also set proxy
                var self = new ObjC.Object(args[0]);
                self.setConnectionProxyDictionary_({
                    "HTTPEnable": 1,
                    "HTTPProxy": PROXY_HOST,
                    "HTTPPort": PROXY_PORT,
                    "HTTPSEnable": 1,
                    "HTTPSProxy": PROXY_HOST,
                    "HTTPSPort": PROXY_PORT
                });
            }
        });

    } catch(e) {
        console.log("[-] NSURLSession hooks failed: " + e);
    }

    // SecTrust bypass
    try {
        Interceptor.replace(Module.findExportByName(null, 'SecTrustEvaluate'), new NativeCallback(function(trust, result) {
            Memory.writePointer(result, ptr(0x1)); // kSecTrustResultProceed
            return 0; // errSecSuccess
        }, 'int', ['pointer', 'pointer']));
        console.log("[+] SecTrustEvaluate bypassed");
    } catch(e) {}

    try {
        Interceptor.replace(Module.findExportByName(null, 'SecTrustEvaluateWithError'), new NativeCallback(function(trust, error) {
            if (!error.isNull()) {
                Memory.writePointer(error, ptr(0x0));
            }
            return 1; // true
        }, 'bool', ['pointer', 'pointer']));
        console.log("[+] SecTrustEvaluateWithError bypassed");
    } catch(e) {}

    // TLS/SSL verification bypass
    try {
        Interceptor.replace(Module.findExportByName(null, 'tls_helper_create_peer_trust'), new NativeCallback(function() {
            return 0; // noErr
        }, 'int', []));
    } catch(e) {}

    try {
        Interceptor.replace(Module.findExportByName(null, 'nw_tls_create_peer_trust'), new NativeCallback(function() {
            return 0; // noErr
        }, 'int', []));
    } catch(e) {}

    // SSLSetSessionOption bypass
    try {
        Interceptor.replace(Module.findExportByName(null, 'SSLSetSessionOption'), new NativeCallback(function(context, option, value) {
            return 0; // noErr
        }, 'int', ['pointer', 'int', 'bool']));
    } catch(e) {}

    // SSLHandshake bypass
    try {
        Interceptor.replace(Module.findExportByName(null, 'SSLHandshake'), new NativeCallback(function(context) {
            return 0; // noErr
        }, 'int', ['pointer']));
    } catch(e) {}
}

// ============= NETWORK MONITORING =============
if (ObjC.available) {
    // Monitor all network requests
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        ['- dataTaskWithRequest:completionHandler:', '- dataTaskWithURL:completionHandler:'].forEach(function(method) {
            if (NSURLSession[method]) {
                Interceptor.attach(NSURLSession[method].implementation, {
                    onEnter: function(args) {
                        var request = new ObjC.Object(args[2]);
                        if (request.URL) {
                            var url = request.URL().absoluteString().toString();
                            if (url.includes("doordash") || url.includes("dasher")) {
                                console.log("[>] Request: " + url.substring(0, 100));

                                // Check for systemVersion in URL
                                if (url.includes("systemVersion=16")) {
                                    console.log("[!] WARNING: iOS 16 detected in URL!");
                                }
                            }
                        }
                    }
                });
            }
        });
    } catch(e) {}
}

// ============= FINAL STATUS =============
console.log("==============================================");
console.log("[+] DoorDash Complete Bypass Active!");
console.log("[+] Device spoofed as: iOS " + SPOOFED_IOS);
console.log("[+] Proxy routing to: " + PROXY_HOST + ":" + PROXY_PORT);
console.log("[+] SSL pinning: BYPASSED");
console.log("[+] Ready to intercept traffic!");
console.log("==============================================");
console.log("[!] Now try 'Dash Now' in the app");
console.log("[!] Traffic should appear in HTTP Toolkit");