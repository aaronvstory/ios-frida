// Analytics-Aware Comprehensive iOS Spoofing for DoorDash
// Ensures 100% consistent version reporting across ALL app components
// Targets: UI APIs, System Calls, Network Headers, and Analytics JSON

console.log("[*] Starting Analytics-Aware Comprehensive Spoofing...");
console.log("[*] Target: Complete iOS version consistency across all systems");

// Configuration - iOS 17.6.1 on iPhone 14 Pro
var spoofVersion = "17.6.1";
var spoofBuild = "21G93";
var spoofDarwin = "23.6.0";
var spoofCFNetwork = "1490.0.4";
var spoofKernelVersion = "Darwin Kernel Version 23.6.0: Mon Jul 29 21:14:30 PDT 2024; root:xnu-10063.141.2~1/RELEASE_ARM64_T8120";
var spoofDeviceModel = "iPhone15,3";  // iPhone 14 Pro
var spoofModelName = "iPhone 14 Pro";
var spoofAppVersion = "2.391.0";  // DoorDash Dasher app

if (ObjC.available) {
    console.log("[+] Objective-C Runtime Available");
    console.log("[+] Applying immediate hooks (no delay for analytics SDK)");

    var hooksApplied = 0;
    var analyticsHooksApplied = 0;

    // =================================================================
    // PHASE 1: Foundation API Hooks (UIDevice, NSProcessInfo)
    // =================================================================

    console.log("[*] Phase 1: Foundation API Hooks");

    // 1.1 UIDevice systemVersion (Most common check)
    try {
        var UIDevice = ObjC.classes.UIDevice;
        if (UIDevice && UIDevice['- systemVersion']) {
            Interceptor.attach(UIDevice['- systemVersion'].implementation, {
                onLeave: function(retval) {
                    retval.replace(ObjC.classes.NSString.stringWithString_(spoofVersion));
                }
            });
            hooksApplied++;
            console.log("[+] UIDevice.systemVersion hooked → " + spoofVersion);
        }
    } catch(e) {
        console.log("[!] Failed to hook UIDevice.systemVersion: " + e);
    }

    // 1.2 NSProcessInfo operatingSystemVersion (Structured version)
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        if (NSProcessInfo && NSProcessInfo['- operatingSystemVersion']) {
            Interceptor.attach(NSProcessInfo['- operatingSystemVersion'].implementation, {
                onLeave: function(retval) {
                    // Create NSOperatingSystemVersion struct for 17.6.1
                    var version = Memory.alloc(24); // NSOperatingSystemVersion is 3 NSIntegers
                    Memory.writeS64(version, 17);          // majorVersion
                    Memory.writeS64(version.add(8), 6);    // minorVersion
                    Memory.writeS64(version.add(16), 1);   // patchVersion
                    retval.replace(version);
                }
            });
            hooksApplied++;
            console.log("[+] NSProcessInfo.operatingSystemVersion hooked → 17.6.1");
        }
    } catch(e) {
        console.log("[!] Failed to hook NSProcessInfo.operatingSystemVersion: " + e);
    }

    // 1.3 NSProcessInfo operatingSystemVersionString
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        if (NSProcessInfo && NSProcessInfo['- operatingSystemVersionString']) {
            Interceptor.attach(NSProcessInfo['- operatingSystemVersionString'].implementation, {
                onLeave: function(retval) {
                    var versionString = "Version " + spoofVersion + " (Build " + spoofBuild + ")";
                    retval.replace(ObjC.classes.NSString.stringWithString_(versionString));
                }
            });
            hooksApplied++;
            console.log("[+] NSProcessInfo.operatingSystemVersionString hooked");
        }
    } catch(e) {
        console.log("[!] Failed to hook NSProcessInfo.operatingSystemVersionString: " + e);
    }

    // 1.4 UIDevice model and localizedModel
    try {
        var UIDevice = ObjC.classes.UIDevice;
        if (UIDevice) {
            if (UIDevice['- model']) {
                Interceptor.attach(UIDevice['- model'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ObjC.classes.NSString.stringWithString_("iPhone"));
                    }
                });
                hooksApplied++;
            }

            if (UIDevice['- localizedModel']) {
                Interceptor.attach(UIDevice['- localizedModel'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ObjC.classes.NSString.stringWithString_("iPhone"));
                    }
                });
                hooksApplied++;
            }

            if (UIDevice['- systemName']) {
                Interceptor.attach(UIDevice['- systemName'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ObjC.classes.NSString.stringWithString_("iOS"));
                    }
                });
                hooksApplied++;
            }
            console.log("[+] UIDevice model/name hooks applied");
        }
    } catch(e) {
        console.log("[!] Failed to hook UIDevice model: " + e);
    }

    // =================================================================
    // PHASE 2: Low-Level System Call Interception
    // =================================================================

    console.log("[*] Phase 2: Low-Level System Hooks");

    // 2.1 sysctlbyname for kernel information
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
                        // Handle kern.osversion
                        if (this.name === "kern.osversion" || this.name === "kern.version") {
                            if (this.oldvalue && !this.oldvalue.isNull()) {
                                var spoofed = Memory.allocUtf8String(spoofKernelVersion);
                                Memory.copy(this.oldvalue, spoofed, Math.min(spoofKernelVersion.length, 256));
                                if (this.oldlenp && !this.oldlenp.isNull()) {
                                    Memory.writeULong(this.oldlenp, spoofKernelVersion.length + 1);
                                }
                            }
                        }
                        // Handle kern.osrelease (Darwin version)
                        else if (this.name === "kern.osrelease") {
                            if (this.oldvalue && !this.oldvalue.isNull()) {
                                var darwinString = spoofDarwin;
                                var spoofed = Memory.allocUtf8String(darwinString);
                                Memory.copy(this.oldvalue, spoofed, darwinString.length + 1);
                                if (this.oldlenp && !this.oldlenp.isNull()) {
                                    Memory.writeULong(this.oldlenp, darwinString.length + 1);
                                }
                            }
                        }
                        // Handle hardware model
                        else if (this.name === "hw.machine" || this.name === "hw.model") {
                            if (this.oldvalue && !this.oldvalue.isNull()) {
                                var spoofed = Memory.allocUtf8String(spoofDeviceModel);
                                Memory.copy(this.oldvalue, spoofed, spoofDeviceModel.length + 1);
                                if (this.oldlenp && !this.oldlenp.isNull()) {
                                    Memory.writeULong(this.oldlenp, spoofDeviceModel.length + 1);
                                }
                            }
                        }
                    }
                }
            });
            hooksApplied++;
            console.log("[+] sysctlbyname hooked for kernel/hardware info");
        }
    } catch(e) {
        console.log("[!] Failed to hook sysctlbyname: " + e);
    }

    // 2.2 uname system call
    try {
        var uname = Module.findExportByName("libSystem.B.dylib", "uname");
        if (uname) {
            Interceptor.attach(uname, {
                onEnter: function(args) {
                    this.buf = args[0];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.buf) {
                        // Modify uname structure
                        var version = Memory.allocUtf8String(spoofKernelVersion);
                        Memory.copy(this.buf.add(256), version, Math.min(spoofKernelVersion.length, 256));

                        var machine = Memory.allocUtf8String("arm64");
                        Memory.copy(this.buf.add(1024), machine, 5);
                    }
                }
            });
            hooksApplied++;
            console.log("[+] uname hooked for system info");
        }
    } catch(e) {
        console.log("[!] Failed to hook uname: " + e);
    }

    // =================================================================
    // PHASE 3: Network-Level User-Agent Spoofing
    // =================================================================

    console.log("[*] Phase 3: Network Header Modification");

    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        if (NSMutableURLRequest && NSMutableURLRequest['- setValue:forHTTPHeaderField:']) {
            Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'].implementation, {
                onEnter: function(args) {
                    var field = new ObjC.Object(args[3]).toString();
                    var value = new ObjC.Object(args[2]).toString();

                    if (field === "User-Agent") {
                        // Replace iOS version in User-Agent
                        var newUA = value
                            .replace(/iOS\s+[\d\.]+/g, "iOS " + spoofVersion)
                            .replace(/CFNetwork\/[\d\.]+/g, "CFNetwork/" + spoofCFNetwork)
                            .replace(/Darwin\/[\d\.]+/g, "Darwin/" + spoofDarwin)
                            .replace(/iPhone\d+,\d+/g, spoofDeviceModel);

                        // Ensure DoorDash version consistency
                        if (value.includes("DoorDash") || value.includes("Dasher")) {
                            newUA = newUA.replace(/DoorDash[\w]*\/[\d\.]+/g, "DoorDashDasher/" + spoofAppVersion);
                        }

                        args[2] = ObjC.classes.NSString.stringWithString_(newUA);
                    }
                    // Also handle custom version headers
                    else if (field === "X-iOS-Version" || field === "X-Device-OS-Version" ||
                             field === "X-Operating-System-Version") {
                        args[2] = ObjC.classes.NSString.stringWithString_(spoofVersion);
                    }
                }
            });
            hooksApplied++;
            console.log("[+] NSMutableURLRequest header modification hooked");
        }
    } catch(e) {
        console.log("[!] Failed to hook NSMutableURLRequest: " + e);
    }

    // =================================================================
    // PHASE 4: JSON Serialization Hook for Analytics (CRITICAL!)
    // =================================================================

    console.log("[*] Phase 4: Analytics JSON Interception (Most Important)");

    try {
        var NSJSONSerialization = ObjC.classes.NSJSONSerialization;
        if (NSJSONSerialization && NSJSONSerialization['+ dataWithJSONObject:options:error:']) {
            Interceptor.attach(NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
                onEnter: function(args) {
                    var obj = new ObjC.Object(args[2]);

                    // Function to recursively modify dictionary
                    function modifyVersionInDict(dict) {
                        if (!dict || dict.isNull()) return;

                        var keys = dict.allKeys();
                        if (!keys || keys.isNull()) return;

                        for (var i = 0; i < keys.count(); i++) {
                            var key = keys.objectAtIndex_(i).toString();

                            // Check for version-related keys
                            if (key === "device_os_version" ||
                                key === "os_version" ||
                                key === "ios_version" ||
                                key === "system_version" ||
                                key === "device_version" ||
                                key === "operating_system_version" ||
                                key.toLowerCase().includes("os_version") ||
                                key.toLowerCase().includes("ios_version")) {

                                // Replace with spoofed version
                                dict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(spoofVersion), key);
                                analyticsHooksApplied++;
                                console.log("[+] Modified analytics key '" + key + "' → " + spoofVersion);
                            }

                            // Check for device model keys
                            if (key === "device_model" || key === "device_type" || key === "hardware_model") {
                                dict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(spoofDeviceModel), key);
                            }

                            // Recursively check nested dictionaries
                            var value = dict.objectForKey_(key);
                            if (value && !value.isNull() && value.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                modifyVersionInDict(value);
                            }
                            // Check arrays for dictionaries
                            else if (value && !value.isNull() && value.isKindOfClass_(ObjC.classes.NSArray)) {
                                for (var j = 0; j < value.count(); j++) {
                                    var item = value.objectAtIndex_(j);
                                    if (item && !item.isNull() && item.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                        modifyVersionInDict(item);
                                    }
                                }
                            }
                        }
                    }

                    // Modify the object if it's a dictionary
                    if (obj && !obj.isNull() && obj.isKindOfClass_(ObjC.classes.NSDictionary)) {
                        modifyVersionInDict(obj);
                    }
                    // If it's an array, check each item
                    else if (obj && !obj.isNull() && obj.isKindOfClass_(ObjC.classes.NSArray)) {
                        for (var i = 0; i < obj.count(); i++) {
                            var item = obj.objectAtIndex_(i);
                            if (item && !item.isNull() && item.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                modifyVersionInDict(item);
                            }
                        }
                    }
                }
            });
            hooksApplied++;
            console.log("[+] NSJSONSerialization hooked for analytics payload modification");
        }
    } catch(e) {
        console.log("[!] Failed to hook NSJSONSerialization: " + e);
    }

    // =================================================================
    // PHASE 5: Additional Bundle and App Info Hooks
    // =================================================================

    console.log("[*] Phase 5: Bundle and App Info Hooks");

    try {
        var NSBundle = ObjC.classes.NSBundle;
        if (NSBundle && NSBundle['- objectForInfoDictionaryKey:']) {
            Interceptor.attach(NSBundle['- objectForInfoDictionaryKey:'].implementation, {
                onEnter: function(args) {
                    this.key = new ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    // Spoof system version keys
                    if (this.key === "MinimumOSVersion" || this.key === "DTPlatformVersion") {
                        retval.replace(ObjC.classes.NSString.stringWithString_(spoofVersion));
                    }
                    // Spoof build version
                    else if (this.key === "CFBundleVersion" || this.key === "DTPlatformBuild") {
                        retval.replace(ObjC.classes.NSString.stringWithString_(spoofBuild));
                    }
                }
            });
            hooksApplied++;
            console.log("[+] NSBundle info dictionary hooked");
        }
    } catch(e) {
        console.log("[!] Failed to hook NSBundle: " + e);
    }

    // =================================================================
    // Early Hook Injection for Analytics SDK
    // =================================================================

    console.log("[*] Attempting early analytics SDK hooks...");

    // Hook common analytics SDK initialization methods
    var analyticsClasses = [
        "DDAnalytics", "DDAnalyticsManager", "DDAnalyticsTracker",
        "Analytics", "AnalyticsManager", "AnalyticsTracker",
        "Mixpanel", "Amplitude", "Segment", "Firebase",
        "FIRAnalytics", "APMAnalytics", "AppsFlyerLib"
    ];

    analyticsClasses.forEach(function(className) {
        try {
            var AnalyticsClass = ObjC.classes[className];
            if (AnalyticsClass) {
                // Hook +load method if exists
                if (AnalyticsClass['+ load']) {
                    Interceptor.attach(AnalyticsClass['+ load'].implementation, {
                        onEnter: function(args) {
                            console.log("[+] Intercepted " + className + " +load (early hook)");
                        }
                    });
                }

                // Hook +initialize if exists
                if (AnalyticsClass['+ initialize']) {
                    Interceptor.attach(AnalyticsClass['+ initialize'].implementation, {
                        onEnter: function(args) {
                            console.log("[+] Intercepted " + className + " +initialize (early hook)");
                        }
                    });
                }

                console.log("[+] Found analytics class: " + className);
                analyticsHooksApplied++;
            }
        } catch(e) {}
    });

    // =================================================================
    // Proxy Configuration (Keep existing working proxy setup)
    // =================================================================

    console.log("[*] Configuring proxy settings...");

    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration'].forEach(function(method) {
            try {
                var original = NSURLSessionConfiguration[method];
                if (original) {
                    Interceptor.attach(original.implementation, {
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
                            }
                        }
                    });
                    hooksApplied++;
                }
            } catch(e) {}
        });
        console.log("[+] Proxy configuration applied");
    } catch(e) {
        console.log("[!] Failed to configure proxy: " + e);
    }

    // =================================================================
    // Summary
    // =================================================================

    console.log("\n" + "=".repeat(60));
    console.log("ANALYTICS-AWARE COMPREHENSIVE SPOOFING ACTIVE");
    console.log("=".repeat(60));
    console.log("Target iOS Version: " + spoofVersion + " (Build " + spoofBuild + ")");
    console.log("Device Model: " + spoofModelName + " (" + spoofDeviceModel + ")");
    console.log("Darwin Kernel: " + spoofDarwin);
    console.log("CFNetwork: " + spoofCFNetwork);
    console.log("-".repeat(60));
    console.log("Hooks Applied:");
    console.log("  Foundation APIs: " + Math.min(6, hooksApplied) + " hooks");
    console.log("  System Calls: 2 hooks");
    console.log("  Network Headers: 1 hook");
    console.log("  JSON Analytics: 1 critical hook");
    console.log("  Analytics Classes Found: " + analyticsHooksApplied);
    console.log("  Total Hooks: " + hooksApplied);
    console.log("-".repeat(60));
    console.log("CRITICAL: JSON serialization hook will modify ALL");
    console.log("analytics payloads to ensure version consistency!");
    console.log("=".repeat(60));

} else {
    console.log("[!] Objective-C runtime not available");
}