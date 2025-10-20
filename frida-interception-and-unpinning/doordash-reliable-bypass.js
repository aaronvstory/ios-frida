// DoorDash Reliable Bypass - Uses only proven working hooks
// Focuses on methods that don't fail with "unable to intercept function" errors

var spoofVersion = "17.6.1";
var spoofBuild = "21H71";
var spoofCFNetwork = "1490.0.4";
var spoofDarwin = "23.6.0";

// Proxy settings
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

console.log("[*] Starting DoorDash Reliable Bypass...");
console.log("[+] Only using proven working hooks");
console.log("[+] Spoofing iOS " + spoofVersion);

if (ObjC.available) {
    // ========== IOS VERSION SPOOFING (WORKING) ==========

    try {
        // UIDevice systemVersion - WORKS
        var UIDevice = ObjC.classes.UIDevice;
        if (UIDevice && UIDevice['- systemVersion']) {
            Interceptor.attach(UIDevice['- systemVersion'], {
                onLeave: function(retval) {
                    var fakeVersion = ObjC.classes.NSString.stringWithString_(spoofVersion);
                    retval.replace(fakeVersion);
                    console.log("[+] iOS version spoofed to: " + spoofVersion);
                }
            });
        }

        // NSProcessInfo operatingSystemVersionString - WORKS
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        if (NSProcessInfo && NSProcessInfo['- operatingSystemVersionString']) {
            Interceptor.attach(NSProcessInfo['- operatingSystemVersionString'], {
                onLeave: function(retval) {
                    var fakeString = ObjC.classes.NSString.stringWithString_("Version " + spoofVersion + " (Build " + spoofBuild + ")");
                    retval.replace(fakeString);
                }
            });
        }
    } catch(e) {
        console.log("[-] iOS version spoofing error: " + e);
    }

    // ========== NETWORK CONFIGURATION (WORKING METHODS ONLY) ==========

    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

        // Create proxy dictionary
        function createProxyDict() {
            var dict = ObjC.classes.NSMutableDictionary.dictionary();
            dict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
            dict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
            dict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
            dict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
            dict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
            dict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");
            return dict;
        }

        // Hook ephemeralSessionConfiguration (WORKS)
        if (NSURLSessionConfiguration['+ ephemeralSessionConfiguration']) {
            Interceptor.attach(NSURLSessionConfiguration['+ ephemeralSessionConfiguration'], {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        var config = new ObjC.Object(retval);
                        config.setConnectionProxyDictionary_(createProxyDict());
                        config.setAllowsCellularAccess_(1);
                        config.setTimeoutIntervalForRequest_(60);
                        console.log("[+] Configured ephemeral session with proxy");
                    }
                }
            });
        }

        // Hook backgroundSessionConfigurationWithIdentifier (WORKS)
        if (NSURLSessionConfiguration['+ backgroundSessionConfigurationWithIdentifier:']) {
            Interceptor.attach(NSURLSessionConfiguration['+ backgroundSessionConfigurationWithIdentifier:'], {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        var config = new ObjC.Object(retval);
                        config.setConnectionProxyDictionary_(createProxyDict());
                        console.log("[+] Configured background session with proxy");
                    }
                }
            });
        }

        // Hook NSMutableURLRequest to add headers (WORKS)
        if (NSMutableURLRequest['- setValue:forHTTPHeaderField:']) {
            Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'], {
                onEnter: function(args) {
                    var field = new ObjC.Object(args[3]).toString();

                    // Intercept User-Agent to add our CFNetwork version
                    if (field === "User-Agent") {
                        var value = new ObjC.Object(args[2]).toString();
                        if (value.indexOf("CFNetwork") === -1) {
                            var newValue = value + " CFNetwork/" + spoofCFNetwork + " Darwin/" + spoofDarwin;
                            args[2] = ObjC.classes.NSString.stringWithString_(newValue);
                            console.log("[+] Modified User-Agent with CFNetwork/" + spoofCFNetwork);
                        }
                    }
                }
            });
        }

        // Hook NSMutableURLRequest initWithURL (WORKS)
        if (NSMutableURLRequest['- initWithURL:']) {
            Interceptor.attach(NSMutableURLRequest['- initWithURL:'], {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        var request = new ObjC.Object(retval);

                        // Add CFNetwork to User-Agent
                        var currentUA = request.valueForHTTPHeaderField_("User-Agent");
                        if (currentUA) {
                            var uaString = currentUA.toString();
                            if (uaString.indexOf("CFNetwork") === -1) {
                                var newUA = uaString + " CFNetwork/" + spoofCFNetwork + " Darwin/" + spoofDarwin;
                                request.setValue_forHTTPHeaderField_(newUA, "User-Agent");
                            }
                        }
                    }
                }
            });
        }
    } catch(e) {
        console.log("[-] Network configuration error: " + e);
    }

    // ========== SSL BYPASS (PROVEN METHODS) ==========

    try {
        // SecTrustEvaluate bypass
        var SecTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                console.log("[*] Bypassing SecTrustEvaluate");
                Memory.writePointer(result, ptr(0x1));
                return 0;
            }, 'int', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluate hooked");
        }

        // SecTrustEvaluateWithError bypass
        var SecTrustEvaluateWithError = Module.findExportByName(null, "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                console.log("[*] Bypassing SecTrustEvaluateWithError");
                if (!error.isNull()) {
                    Memory.writePointer(error, ptr(0x0));
                }
                return 1;
            }, 'bool', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluateWithError hooked");
        }

        // tls_helper_create_peer_trust bypass
        var tls_helper = Module.findExportByName(null, "tls_helper_create_peer_trust");
        if (tls_helper) {
            Interceptor.replace(tls_helper, new NativeCallback(function() {
                console.log("[*] Bypassing tls_helper_create_peer_trust");
                return 0;
            }, 'int', []));
            console.log("[+] tls_helper_create_peer_trust hooked");
        }

    } catch(e) {
        console.log("[-] SSL bypass error: " + e);
    }

    // ========== DOORDASH SPECIFIC HOOKS ==========

    try {
        // Hook NSBundle to spoof app version
        var NSBundle = ObjC.classes.NSBundle;
        if (NSBundle && NSBundle['- objectForInfoDictionaryKey:']) {
            Interceptor.attach(NSBundle['- objectForInfoDictionaryKey:'], {
                onEnter: function(args) {
                    this.key = new ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    if (this.key === "CFBundleShortVersionString") {
                        // Spoof DoorDash app version
                        retval.replace(ObjC.classes.NSString.stringWithString_("2.391.0"));
                        console.log("[+] DoorDash app version spoofed to 2.391.0");
                    }
                    if (this.key === "CFBundleVersion") {
                        retval.replace(ObjC.classes.NSString.stringWithString_("2391"));
                    }
                }
            });
        }

    } catch(e) {
        console.log("[-] DoorDash specific hook error: " + e);
    }

    // ========== SCAN FOR EXISTING SESSIONS ==========

    setTimeout(function() {
        try {
            // Apply proxy to any existing NSURLSessionConfiguration instances
            ObjC.choose(ObjC.classes.NSURLSessionConfiguration, {
                onMatch: function(config) {
                    try {
                        config.setConnectionProxyDictionary_(createProxyDict());
                        console.log("[+] Applied proxy to existing NSURLSessionConfiguration");
                    } catch(e) {}
                },
                onComplete: function() {
                    console.log("[*] Finished configuring existing sessions");
                }
            });
        } catch(e) {}
    }, 1000);

    console.log("[+] DoorDash Reliable Bypass Loaded!");
    console.log("[+] iOS Version: " + spoofVersion);
    console.log("[+] CFNetwork: " + spoofCFNetwork);
    console.log("[+] Proxy: " + proxyHost + ":" + proxyPort);
    console.log("[+] SSL Bypass: Active");
    console.log("[+] Using only proven working hooks");

} else {
    console.log("[-] Objective-C runtime not available");
}