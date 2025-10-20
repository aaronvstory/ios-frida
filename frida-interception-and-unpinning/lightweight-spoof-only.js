// Lightweight iOS Spoofing - Minimal Performance Impact
// Only spoofs essential values without heavy SSL bypassing

console.log("[*] Starting Lightweight Spoofing (Minimal Mode)...");

// Configuration - Essential values only
var spoofVersion = "17.6.1";
var spoofBuild = "21G93";
var spoofDarwin = "23.6.0";
var spoofCFNetwork = "1490.0.4";
var spoofAppVersion = "2.391.0";  // DoorDash Dasher app version

if (ObjC.available) {
    console.log("[+] Lightweight Mode Active - Minimal hooks for best performance");
    console.log("[+] Spoofing iOS " + spoofVersion);
    console.log("[+] CFNetwork: " + spoofCFNetwork);

    var hooksApplied = 0;

    // 1. Hook UIDevice systemVersion (Essential)
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

    // 2. Hook CFNetwork version in User-Agent (Most Important for DoorDash)
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        if (NSMutableURLRequest && NSMutableURLRequest['- setValue:forHTTPHeaderField:']) {
            Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'], {
                onEnter: function(args) {
                    var field = new ObjC.Object(args[3]).toString();

                    if (field === "User-Agent") {
                        var value = new ObjC.Object(args[2]).toString();

                        // Update critical values in User-Agent
                        var newUA = value
                            .replace(/CFNetwork\/[\d\.]+/g, "CFNetwork/" + spoofCFNetwork)
                            .replace(/Darwin\/[\d\.]+/g, "Darwin/" + spoofDarwin)
                            .replace(/iOS\s+[\d\.]+/g, "iOS " + spoofVersion);

                        // Optional: Spoof app version if it's DoorDash
                        if (value.includes("Dasher") || value.includes("DoorDash")) {
                            newUA = newUA.replace(/Dasher\/[\d\.]+/g, "Dasher/" + spoofAppVersion)
                                         .replace(/DoorDash[\w]*\/[\d\.]+/g, "DoorDash/" + spoofAppVersion);
                        }

                        args[2] = ObjC.classes.NSString.stringWithString_(newUA);
                    }
                }
            });
            hooksApplied++;
            console.log("[+] User-Agent hook applied (CFNetwork spoofing)");
        }
    } catch(e) {}

    // 3. Hook NSBundle for app version (Optional - for DoorDash)
    try {
        var NSBundle = ObjC.classes.NSBundle;
        if (NSBundle && NSBundle['- objectForInfoDictionaryKey:']) {
            Interceptor.attach(NSBundle['- objectForInfoDictionaryKey:'], {
                onEnter: function(args) {
                    this.key = new ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    if (this.key === "CFBundleShortVersionString" || this.key === "CFBundleVersion") {
                        // Only spoof if it looks like we're in DoorDash
                        var bundle = ObjC.classes.NSBundle.mainBundle();
                        var bundleId = bundle.bundleIdentifier().toString();

                        if (bundleId.includes("doordash") || bundleId.includes("dasher")) {
                            retval.replace(ObjC.classes.NSString.stringWithString_(spoofAppVersion));
                            console.log("[+] Spoofed app version to " + spoofAppVersion);
                        }
                    }
                }
            });
            hooksApplied++;
        }
    } catch(e) {}

    // 4. Minimal NSProcessInfo hook (only if really needed)
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

    // 5. Simple proxy configuration (no SSL bypass)
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

                                // Simple proxy setup without SSL bypassing
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

    console.log("[+] Lightweight spoofing loaded successfully!");
    console.log("[+] Total hooks applied: " + hooksApplied + " (minimal for performance)");
    console.log("[+] Key values spoofed:");
    console.log("    - iOS Version: " + spoofVersion);
    console.log("    - CFNetwork: " + spoofCFNetwork);
    console.log("    - Darwin: " + spoofDarwin);
    console.log("    - App Version: " + spoofAppVersion + " (if DoorDash)");
    console.log("[+] This mode has minimal performance impact!");

} else {
    console.log("[!] Objective-C runtime not available");
}