// Comprehensive iOS Spoofing - Enhanced DoorDash API Compatibility
// Based on lightweight-spoof-only.js but with additional device fingerprinting

console.log("[*] Starting Comprehensive Spoofing (Enhanced DoorDash Mode)...");

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
    console.log("[+] Comprehensive Mode Active - Enhanced DoorDash compatibility");
    console.log("[+] Spoofing iOS " + spoofVersion + " on " + spoofModelName);
    console.log("[+] CFNetwork: " + spoofCFNetwork + " | Darwin: " + spoofDarwin);

    var hooksApplied = 0;

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

    // 2. UIDevice model (New - Important for device fingerprinting)
    try {
        var UIDevice = ObjC.classes.UIDevice;
        if (UIDevice && UIDevice['- model']) {
            Interceptor.attach(UIDevice['- model'], {
                onLeave: function(retval) {
                    retval.replace(ObjC.classes.NSString.stringWithString_("iPhone"));
                }
            });
            hooksApplied++;
            console.log("[+] Device model hook applied");
        }
    } catch(e) {}

    // 3. UIDevice localizedModel (New)
    try {
        var UIDevice = ObjC.classes.UIDevice;
        if (UIDevice && UIDevice['- localizedModel']) {
            Interceptor.attach(UIDevice['- localizedModel'], {
                onLeave: function(retval) {
                    retval.replace(ObjC.classes.NSString.stringWithString_("iPhone"));
                }
            });
            hooksApplied++;
        }
    } catch(e) {}

    // 4. Enhanced User-Agent spoofing with additional headers
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

                        // Add iPhone model info if not present
                        if (!newUA.includes("iPhone")) {
                            newUA = newUA + " " + spoofModelName.replace(" ", "");
                        }

                        args[2] = ObjC.classes.NSString.stringWithString_(newUA);
                    }

                    // Add additional headers that DoorDash might check
                    if (field === "X-iOS-Version" || field === "X-App-Version") {
                        args[2] = ObjC.classes.NSString.stringWithString_(spoofVersion);
                    }
                }
            });
            hooksApplied++;
            console.log("[+] Enhanced User-Agent hook applied");
        }
    } catch(e) {}

    // 5. NSBundle app version spoofing (Enhanced)
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

    // 6. Enhanced NSProcessInfo spoofing
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        if (NSProcessInfo && NSProcessInfo['- operatingSystemVersionString']) {
            Interceptor.attach(NSProcessInfo['- operatingSystemVersionString'], {
                onLeave: function(retval) {
                    retval.replace(ObjC.classes.NSString.stringWithString_(
                        "Version " + spoofVersion + " (Build " + spoofBuild + ")"
                    ));
                }
            });
            hooksApplied++;
        }
    } catch(e) {}

    // 7. System info spoofing for uname calls (New - Important)
    try {
        var uname = Module.findExportByName("libSystem.B.dylib", "uname");
        if (uname) {
            Interceptor.attach(uname, {
                onEnter: function(args) {
                    this.buf = args[0];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.buf) {
                        // Modify uname structure to match our spoofed iOS version
                        var version = Memory.allocUtf8String(spoofKernelVersion);
                        Memory.copy(this.buf.add(256), version, Math.min(spoofKernelVersion.length, 256));

                        var machine = Memory.allocUtf8String("arm64");
                        Memory.copy(this.buf.add(1024), machine, 5);
                    }
                }
            });
            hooksApplied++;
            console.log("[+] System uname hook applied");
        }
    } catch(e) {}

    // 8. Hardware model spoofing (New - Critical for DoorDash)
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
                            }
                        } else if (this.name === "kern.version") {
                            if (this.oldvalue && !this.oldvalue.isNull()) {
                                var spoofed = Memory.allocUtf8String(spoofKernelVersion);
                                Memory.copy(this.oldvalue, spoofed, Math.min(spoofKernelVersion.length, 256));
                            }
                        }
                    }
                }
            });
            hooksApplied++;
            console.log("[+] Hardware model (sysctlbyname) hook applied");
        }
    } catch(e) {}

    // 9. Basic jailbreak detection bypass (New - Anti-detection)
    try {
        // Hook common jailbreak detection methods
        var NSFileManager = ObjC.classes.NSFileManager;
        if (NSFileManager && NSFileManager['- fileExistsAtPath:']) {
            Interceptor.attach(NSFileManager['- fileExistsAtPath:'], {
                onEnter: function(args) {
                    this.path = new ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    // Return false for common jailbreak paths
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
            console.log("[+] Basic jailbreak detection bypass applied");
        }
    } catch(e) {}

    // 10. Enhanced proxy configuration (same as lightweight)
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

                                // Enhanced proxy setup
                                var proxyDict = ObjC.classes.NSMutableDictionary.dictionary();
                                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_("192.168.50.9"), "HTTPProxy");
                                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(8000), "HTTPPort");
                                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_("192.168.50.9"), "HTTPSProxy");
                                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(8000), "HTTPSPort");

                                config.setConnectionProxyDictionary_(proxyDict);
                            }
                        }
                    });
                    hooksApplied++;
                }
            } catch(e) {}
        });
    } catch(e) {}

    // 11. Additional device capability spoofing (New)
    try {
        var UIDevice = ObjC.classes.UIDevice;
        if (UIDevice && UIDevice['- systemName']) {
            Interceptor.attach(UIDevice['- systemName'], {
                onLeave: function(retval) {
                    retval.replace(ObjC.classes.NSString.stringWithString_("iOS"));
                }
            });
            hooksApplied++;
        }
    } catch(e) {}

    console.log("[+] Comprehensive spoofing loaded successfully!");
    console.log("[+] Total hooks applied: " + hooksApplied + " (enhanced compatibility)");
    console.log("[+] Comprehensive device profile:");
    console.log("    ═══════════════════════════════════════");
    console.log("    Device Model:  " + spoofModelName + " (" + spoofDeviceModel + ")");
    console.log("    iOS Version:   " + spoofVersion + " (Build " + spoofBuild + ")");
    console.log("    Darwin Kernel: " + spoofDarwin);
    console.log("    CFNetwork:     " + spoofCFNetwork);
    console.log("    App Version:   " + spoofAppVersion + " (DoorDash)");
    console.log("    Anti-Detection: Basic jailbreak bypass enabled");
    console.log("    ═══════════════════════════════════════");
    console.log("[+] This should address DoorDash API validation issues!");

} else {
    console.log("[!] Objective-C runtime not available");
}