// Comprehensive iOS Spoofing - Attach Mode (Stay Logged In)
// Enhanced DoorDash API compatibility for running apps

console.log("[*] Starting Comprehensive Spoofing - ATTACH MODE...");
console.log("[*] This version preserves existing login sessions");

// Configuration - Consistent iOS 17.6.1 device profile
var spoofVersion = "17.6.1";
var spoofBuild = "21G93";
var spoofDarwin = "23.6.0";
var spoofCFNetwork = "1490.0.4";
var spoofAppVersion = "2.391.0";  // DoorDash Dasher app version
var spoofDeviceModel = "iPhone15,3";  // iPhone 14 Pro
var spoofModelName = "iPhone 14 Pro";
var spoofKernelVersion = "Darwin Kernel Version 23.6.0: Mon Jul 29 21:14:30 PDT 2024; root:xnu-10063.141.2~1/RELEASE_ARM64_T8120";

if (ObjC.available) {
    console.log("[+] Comprehensive ATTACH Mode Active - Enhanced DoorDash compatibility");
    console.log("[+] Spoofing iOS " + spoofVersion + " on " + spoofModelName);
    console.log("[+] NOTE: Pull to refresh or navigate to activate proxy on existing sessions");

    var hooksApplied = 0;

    // Same hooks as comprehensive-spoof-stable.js but optimized for attach mode

    // 1. UIDevice systemVersion (Essential)
    try {
        var UIDevice = ObjC.classes.UIDevice;
        if (UIDevice && UIDevice['- systemVersion']) {
            Interceptor.attach(UIDevice['- systemVersion'], {
                onLeave: function(retval) {
                    retval.replace(ObjC.classes.NSString.stringWithString_(spoofVersion));
                }
            });
            hooksApplied++;
            console.log("[+] iOS version hook applied");
        }
    } catch(e) {}

    // 2. Enhanced User-Agent spoofing (Most critical for API calls)
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        if (NSMutableURLRequest && NSMutableURLRequest['- setValue:forHTTPHeaderField:']) {
            Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'], {
                onEnter: function(args) {
                    var field = new ObjC.Object(args[3]).toString();
                    var value = new ObjC.Object(args[2]).toString();

                    if (field === "User-Agent") {
                        // Enhanced User-Agent with complete device info
                        var newUA = value
                            .replace(/CFNetwork\/[\d\.]+/g, "CFNetwork/" + spoofCFNetwork)
                            .replace(/Darwin\/[\d\.]+/g, "Darwin/" + spoofDarwin)
                            .replace(/iOS\s+[\d\.]+/g, "iOS " + spoofVersion);

                        // Enhanced DoorDash app version spoofing
                        if (value.includes("Dasher") || value.includes("DoorDash")) {
                            newUA = newUA.replace(/Dasher\/[\d\.]+/g, "Dasher/" + spoofAppVersion)
                                         .replace(/DoorDash[\w]*\/[\d\.]+/g, "DoorDash/" + spoofAppVersion);
                        }

                        args[2] = ObjC.classes.NSString.stringWithString_(newUA);
                        console.log("[*] Spoofed User-Agent for API call: " + newUA.substring(0, 100) + "...");
                    }
                }
            });
            hooksApplied++;
            console.log("[+] Enhanced User-Agent hook applied (attach mode)");
        }
    } catch(e) {}

    // 3. Hardware model spoofing (Critical for device fingerprinting)
    try {
        var sysctlbyname = Module.findExportByName("libSystem.B.dylib", "sysctlbyname");
        if (sysctlbyname) {
            Interceptor.attach(sysctlbyname, {
                onEnter: function(args) {
                    this.name = Memory.readUtf8String(args[0]);
                    this.oldvalue = args[1];
                    this.oldlenp = args[2];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) {
                        if (this.name === "hw.model" || this.name === "hw.machine") {
                            if (this.oldvalue && !this.oldvalue.isNull()) {
                                var spoofed = Memory.allocUtf8String(spoofDeviceModel);
                                Memory.copy(this.oldvalue, spoofed, spoofDeviceModel.length + 1);

                                if (this.oldlenp && !this.oldlenp.isNull()) {
                                    Memory.writeULong(this.oldlenp, spoofDeviceModel.length + 1);
                                }
                                console.log("[*] Spoofed hardware model to: " + spoofDeviceModel);
                            }
                        }
                    }
                }
            });
            hooksApplied++;
            console.log("[+] Hardware model spoofing applied (attach mode)");
        }
    } catch(e) {}

    // 4. NSBundle app version (For version checks)
    try {
        var NSBundle = ObjC.classes.NSBundle;
        if (NSBundle && NSBundle['- objectForInfoDictionaryKey:']) {
            Interceptor.attach(NSBundle['- objectForInfoDictionaryKey:'], {
                onEnter: function(args) {
                    this.key = new ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    var bundle = ObjC.classes.NSBundle.mainBundle();
                    var bundleId = bundle.bundleIdentifier().toString();

                    if (bundleId.includes("doordash") || bundleId.includes("dasher")) {
                        if (this.key === "CFBundleShortVersionString") {
                            retval.replace(ObjC.classes.NSString.stringWithString_(spoofAppVersion));
                        } else if (this.key === "CFBundleVersion") {
                            retval.replace(ObjC.classes.NSString.stringWithString_(spoofBuild));
                        }
                    }
                }
            });
            hooksApplied++;
        }
    } catch(e) {}

    // 5. Basic jailbreak detection bypass
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        if (NSFileManager && NSFileManager['- fileExistsAtPath:']) {
            Interceptor.attach(NSFileManager['- fileExistsAtPath:'], {
                onEnter: function(args) {
                    this.path = new ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    var jailbreakPaths = [
                        "/Applications/Cydia.app",
                        "/bin/bash", "/bin/sh",
                        "/usr/sbin/sshd",
                        "/etc/apt",
                        "/private/var/lib/apt/",
                        "/Applications/Sileo.app",
                        "/usr/bin/ssh"
                    ];

                    for (var i = 0; i < jailbreakPaths.length; i++) {
                        if (this.path.includes(jailbreakPaths[i])) {
                            retval.replace(ptr(0)); // Return NO
                            break;
                        }
                    }
                }
            });
            hooksApplied++;
        }
    } catch(e) {}

    // 6. Lightweight proxy configuration for NEW sessions
    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration'].forEach(function(method) {
            try {
                var original = NSURLSessionConfiguration[method];
                if (original) {
                    Interceptor.attach(original, {
                        onLeave: function(retval) {
                            if (!retval.isNull()) {
                                var config = new ObjC.Object(retval);

                                var proxyDict = ObjC.classes.NSMutableDictionary.dictionary();
                                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_("192.168.50.9"), "HTTPProxy");
                                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(8000), "HTTPPort");
                                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_("192.168.50.9"), "HTTPSProxy");
                                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(8000), "HTTPSPort");

                                config.setConnectionProxyDictionary_(proxyDict);
                                console.log("[*] Proxy configured for new session");
                            }
                        }
                    });
                    hooksApplied++;
                }
            } catch(e) {}
        });
    } catch(e) {}

    console.log("[+] Comprehensive ATTACH mode spoofing loaded successfully!");
    console.log("[+] Total hooks applied: " + hooksApplied + " (attach-optimized)");
    console.log("    ═══════════════════════════════════════");
    console.log("    Mode: ATTACH (preserves login session)");
    console.log("    Device: " + spoofModelName + " (" + spoofDeviceModel + ")");
    console.log("    iOS: " + spoofVersion + " | App: " + spoofAppVersion);
    console.log("    ═══════════════════════════════════════");
    console.log("[!] IMPORTANT: Pull to refresh or navigate to activate proxy");
    console.log("[+] Enhanced spoofing should fix API validation errors!");

} else {
    console.log("[!] Objective-C runtime not available");
}