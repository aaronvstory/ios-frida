// iOS Version Bypass with SSL Pinning Bypass and Proxy Configuration
// Combines iOS version spoofing with SSL bypass for DoorDash compatibility

console.log("[*] Starting iOS Version Bypass with SSL Pinning Bypass...");

// Configuration
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

// iOS Version to spoof (iOS 17.6.1 for DoorDash)
var spoofVersion = "17.6.1";
var spoofBuild = "21G93";
var spoofDarwin = "23.6.0";
var spoofCFNetwork = "1490.0.4";

if (ObjC.available) {
    console.log("[+] iOS Version Bypass Active!");
    console.log("[+] Device will appear as iOS " + spoofVersion);
    console.log("[+] CFNetwork: " + spoofCFNetwork);
    console.log("[+] Darwin: " + spoofDarwin);

    // ========== PART 1: iOS VERSION SPOOFING ==========

    // Hook UIDevice systemVersion
    try {
        var UIDevice = ObjC.classes.UIDevice;
        var systemVersionMethod = UIDevice['- systemVersion'];
        if (systemVersionMethod) {
            Interceptor.attach(systemVersionMethod, {
                onLeave: function(retval) {
                    var fakeVersion = ObjC.classes.NSString.stringWithString_(spoofVersion);
                    retval.replace(fakeVersion);
                    console.log("[+] Spoofed systemVersion to " + spoofVersion);
                }
            });
        }
    } catch(e) {
        console.log("[-] Failed to hook UIDevice: " + e);
    }

    // Hook NSProcessInfo operatingSystemVersionString
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        var versionStringMethod = NSProcessInfo['- operatingSystemVersionString'];
        if (versionStringMethod) {
            Interceptor.attach(versionStringMethod, {
                onLeave: function(retval) {
                    var fakeString = ObjC.classes.NSString.stringWithString_("Version " + spoofVersion + " (Build " + spoofBuild + ")");
                    retval.replace(fakeString);
                }
            });
        }
    } catch(e) {
        console.log("[-] Failed to hook NSProcessInfo: " + e);
    }

    // ========== PART 2: PROXY CONFIGURATION ==========

    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

        // Configure default session
        Interceptor.attach(NSURLSessionConfiguration['+ defaultSessionConfiguration'], {
            onLeave: function(retval) {
                var config = new ObjC.Object(retval);

                // Create proxy dictionary
                var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");

                config.setConnectionProxyDictionary_(proxyDict);
                console.log("[+] Proxy configured for defaultSessionConfiguration");
            }
        });

        // Configure ephemeral session
        Interceptor.attach(NSURLSessionConfiguration['+ ephemeralSessionConfiguration'], {
            onLeave: function(retval) {
                var config = new ObjC.Object(retval);

                var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");

                config.setConnectionProxyDictionary_(proxyDict);
                console.log("[+] Proxy configured for ephemeralSessionConfiguration");
            }
        });

    } catch(e) {
        console.log("[-] Failed to hook NSURLSessionConfiguration: " + e);
    }

    // ========== PART 3: SSL PINNING BYPASS ==========

    // Bypass SecTrustEvaluate
    try {
        var SecTrustEvaluate = Module.findExportByName(null, 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                console.log("[*] Bypassing SecTrustEvaluate");
                Memory.writePointer(result, ptr(0x1)); // kSecTrustResultProceed
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
        }
    } catch(e) {
        console.log("[-] Failed to hook SecTrustEvaluate: " + e);
    }

    // Bypass SecTrustEvaluateWithError
    try {
        var SecTrustEvaluateWithError = Module.findExportByName(null, 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                console.log("[*] Bypassing SecTrustEvaluateWithError");
                Memory.writePointer(error, ptr(0x0)); // No error
                return 1; // True (trusted)
            }, 'bool', ['pointer', 'pointer']));
        }
    } catch(e) {
        console.log("[-] Failed to hook SecTrustEvaluateWithError: " + e);
    }

    // Bypass NSURLSession certificate validation
    try {
        var NSURLSession = ObjC.classes.NSURLSession;

        // Find all NSURLSession delegate methods that handle authentication
        var delegateMethods = [
            '- URLSession:didReceiveChallenge:completionHandler:',
            '- URLSession:task:didReceiveChallenge:completionHandler:'
        ];

        delegateMethods.forEach(function(method) {
            try {
                var impl = NSURLSession[method];
                if (impl) {
                    Interceptor.attach(impl, {
                        onEnter: function(args) {
                            var challenge = new ObjC.Object(args[3]);
                            var completionHandler = new ObjC.Block(args[4]);

                            // Get the protection space
                            var protectionSpace = challenge.protectionSpace();
                            var authMethod = protectionSpace.authenticationMethod();

                            // If it's a server trust challenge, bypass it
                            if (authMethod.isEqualToString_("NSURLAuthenticationMethodServerTrust")) {
                                console.log("[*] Bypassing SSL certificate validation");
                                var credential = ObjC.classes.NSURLCredential.credentialForTrust_(protectionSpace.serverTrust());
                                completionHandler.implementation(0, credential, null); // Use credential

                                // Prevent original handler from running
                                return;
                            }
                        }
                    });
                }
            } catch(e) {
                // Method might not exist for this class
            }
        });
    } catch(e) {
        console.log("[-] Failed to hook NSURLSession delegates: " + e);
    }

    // Hook HTTP Headers to include iOS version info
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        var setValueMethod = NSMutableURLRequest['- setValue:forHTTPHeaderField:'];

        if (setValueMethod) {
            Interceptor.attach(setValueMethod, {
                onEnter: function(args) {
                    var field = new ObjC.Object(args[3]);
                    var value = new ObjC.Object(args[2]);

                    // Update User-Agent if it contains iOS version
                    if (field.toString() === "User-Agent" && value.toString().includes("iOS")) {
                        var newUserAgent = value.toString()
                            .replace(/iOS\s+[\d\.]+/g, "iOS " + spoofVersion)
                            .replace(/Darwin\/[\d\.]+/g, "Darwin/" + spoofDarwin)
                            .replace(/CFNetwork\/[\d\.]+/g, "CFNetwork/" + spoofCFNetwork);

                        args[2] = ObjC.classes.NSString.stringWithString_(newUserAgent);
                        console.log("[+] Updated User-Agent with iOS " + spoofVersion);
                    }
                }
            });
        }
    } catch(e) {
        console.log("[-] Failed to hook NSMutableURLRequest: " + e);
    }

    // Hook AFNetworking if present
    try {
        var AFHTTPSessionManager = ObjC.classes.AFHTTPSessionManager;
        if (AFHTTPSessionManager) {
            var securityPolicy = AFHTTPSessionManager['- setSecurityPolicy:'];
            if (securityPolicy) {
                Interceptor.attach(securityPolicy, {
                    onEnter: function(args) {
                        var policy = new ObjC.Object(args[2]);
                        policy.setAllowInvalidCertificates_(true);
                        policy.setValidatesDomainName_(false);
                        console.log("[*] Disabled AFNetworking certificate validation");
                    }
                });
            }
        }
    } catch(e) {
        // AFNetworking might not be present
    }

    // Hook Alamofire if present
    try {
        var ServerTrustPolicy = ObjC.classes.ServerTrustPolicy;
        if (ServerTrustPolicy) {
            var evaluate = ServerTrustPolicy['- evaluateServerTrust:forHost:'];
            if (evaluate) {
                Interceptor.attach(evaluate, {
                    onLeave: function(retval) {
                        retval.replace(ptr(0x1)); // Return true (trusted)
                        console.log("[*] Bypassed Alamofire certificate validation");
                    }
                });
            }
        }
    } catch(e) {
        // Alamofire might not be present
    }

    console.log("[+] iOS Version Bypass and SSL Pinning Bypass loaded successfully!");
    console.log("[+] Traffic should now appear in HTTP Toolkit");

} else {
    console.log("[!] Objective-C runtime not available");
}