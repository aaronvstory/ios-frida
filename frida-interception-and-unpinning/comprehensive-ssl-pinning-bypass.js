// Comprehensive SSL Pinning Bypass with Proxy Configuration
// Handles all major SSL pinning implementations on iOS
// Works with DoorDash and other heavily protected apps

console.log("[*] Starting Comprehensive SSL Pinning Bypass with Proxy...");

// Proxy configuration - adjust to your HTTP Toolkit settings
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

if (ObjC.available) {
    try {
        // ============================
        // PROXY CONFIGURATION
        // ============================
        
        // Hook NSURLSessionConfiguration to set proxy
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        
        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration'].forEach(function(method) {
            var original = NSURLSessionConfiguration[method];
            if (original) {
                Interceptor.attach(original.implementation, {
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
                        
                        // Add exceptions to prevent DNS issues
                        var exceptionsArray = ObjC.classes.NSMutableArray.alloc().init();
                        exceptionsArray.addObject_("*.local");
                        exceptionsArray.addObject_("localhost");
                        exceptionsArray.addObject_("127.0.0.1");
                        proxyDict.setObject_forKey_(exceptionsArray, "ExceptionsList");
                        
                        config.setConnectionProxyDictionary_(proxyDict);
                        console.log("[+] Proxy configured for " + method);
                    }
                });
            }
        });

        // ============================
        // SSL PINNING BYPASS - LEVEL 1: SecTrust Functions
        // ============================
        
        // SecTrustEvaluate - Classic bypass
        var SecTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                console.log("[*] Bypassing SecTrustEvaluate");
                Memory.writeU32(result, 0); // kSecTrustResultProceed = 0
                return 0; // Success
            }, 'int', ['pointer', 'pointer']));
        }
        
        // SecTrustEvaluateWithError - iOS 12+ bypass
        var SecTrustEvaluateWithError = Module.findExportByName(null, "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                console.log("[*] Bypassing SecTrustEvaluateWithError");
                if (error !== 0) {
                    Memory.writePointer(error, ptr(0));
                }
                return 1; // true - trust is valid
            }, 'bool', ['pointer', 'pointer']));
        }

        // SecTrustEvaluateAsyncWithError - Async variant
        var SecTrustEvaluateAsyncWithError = Module.findExportByName(null, "SecTrustEvaluateAsyncWithError");
        if (SecTrustEvaluateAsyncWithError) {
            Interceptor.replace(SecTrustEvaluateAsyncWithError, new NativeCallback(function(trust, queue, handler) {
                console.log("[*] Bypassing SecTrustEvaluateAsyncWithError");
                var block = new ObjC.Block(handler);
                var callback = block.implementation;
                callback(trust, 1, ptr(0)); // trust, true, no error
                return 0;
            }, 'int', ['pointer', 'pointer', 'pointer']));
        }

        // SecTrustGetTrustResult - Additional bypass
        var SecTrustGetTrustResult = Module.findExportByName(null, "SecTrustGetTrustResult");
        if (SecTrustGetTrustResult) {
            Interceptor.replace(SecTrustGetTrustResult, new NativeCallback(function(trust, result) {
                console.log("[*] Bypassing SecTrustGetTrustResult");
                Memory.writeU32(result, 0); // kSecTrustResultProceed
                return 0;
            }, 'int', ['pointer', 'pointer']));
        }

        // ============================
        // SSL PINNING BYPASS - LEVEL 2: NSURLSession Delegates
        // ============================
        
        // Find all loaded classes and hook SSL validation methods
        var classNames = ObjC.enumerateLoadedClassesSync();
        var hookCount = 0;
        
        classNames.forEach(function(className) {
            try {
                var clazz = ObjC.classes[className];
                
                // Hook URLSession:didReceiveChallenge:completionHandler:
                var method1 = clazz['- URLSession:didReceiveChallenge:completionHandler:'];
                if (method1) {
                    Interceptor.attach(method1.implementation, {
                        onEnter: function(args) {
                            console.log("[*] Bypassing SSL in class: " + className);
                            var challenge = new ObjC.Object(args[3]);
                            var completionHandler = new ObjC.Block(args[4]);
                            
                            // Get the protection space and trust
                            var protectionSpace = challenge.protectionSpace();
                            var trust = protectionSpace.serverTrust();
                            
                            // Create credential from trust
                            var credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                            
                            // Call completion handler with credential
                            var callback = completionHandler.implementation;
                            callback(0, credential); // NSURLSessionAuthChallengeUseCredential = 0
                        }
                    });
                    hookCount++;
                }
                
                // Hook URLSession:task:didReceiveChallenge:completionHandler:
                var method2 = clazz['- URLSession:task:didReceiveChallenge:completionHandler:'];
                if (method2) {
                    Interceptor.attach(method2.implementation, {
                        onEnter: function(args) {
                            console.log("[*] Bypassing SSL in task for class: " + className);
                            var challenge = new ObjC.Object(args[4]);
                            var completionHandler = new ObjC.Block(args[5]);
                            
                            var protectionSpace = challenge.protectionSpace();
                            var trust = protectionSpace.serverTrust();
                            var credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                            
                            var callback = completionHandler.implementation;
                            callback(0, credential);
                        }
                    });
                    hookCount++;
                }
                
            } catch(e) {
                // Some classes might not be accessible
            }
        });
        
        console.log("[+] Hooked " + hookCount + " SSL validation methods");

        // ============================
        // SSL PINNING BYPASS - LEVEL 3: TrustKit
        // ============================
        
        try {
            var TrustKit = ObjC.classes.TrustKit;
            if (TrustKit) {
                Interceptor.attach(TrustKit['- pinningValidator'].implementation, {
                    onLeave: function(retval) {
                        console.log("[*] Bypassing TrustKit pinning");
                        retval.replace(ptr(0));
                    }
                });
            }
        } catch(e) {}

        // ============================
        // SSL PINNING BYPASS - LEVEL 4: AFNetworking
        // ============================
        
        try {
            var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
            if (AFSecurityPolicy) {
                // Force allow invalid certificates
                Interceptor.attach(AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
                    onEnter: function(args) {
                        args[2] = ptr(0x1);
                        console.log("[*] AFNetworking: Forced allowInvalidCertificates = YES");
                    }
                });
                
                Interceptor.attach(AFSecurityPolicy['- allowInvalidCertificates'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ptr(0x1));
                    }
                });
                
                // Disable SSL pinning
                Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                    onEnter: function(args) {
                        args[2] = ptr(0); // AFSSLPinningModeNone = 0
                        console.log("[*] AFNetworking: Forced SSLPinningMode = None");
                    }
                });
                
                // Force validation to always succeed
                Interceptor.attach(AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ptr(0x1));
                        console.log("[*] AFNetworking: Forced evaluateServerTrust = YES");
                    }
                });
            }
        } catch(e) {}

        // ============================
        // SSL PINNING BYPASS - LEVEL 5: Alamofire
        // ============================
        
        try {
            var ServerTrustPolicy = ObjC.classes.ServerTrustPolicy;
            if (ServerTrustPolicy) {
                Interceptor.attach(ServerTrustPolicy['- evaluateServerTrust:forHost:'].implementation, {
                    onLeave: function(retval) {
                        console.log("[*] Alamofire: Bypassing ServerTrustPolicy");
                        retval.replace(ptr(0x1));
                    }
                });
            }
        } catch(e) {}

        // ============================
        // SSL PINNING BYPASS - LEVEL 6: Custom Certificate Validation
        // ============================
        
        // Hook common certificate validation method patterns
        var validationKeywords = ['verify', 'Verif', 'valid', 'Valid', 'pinning', 'Pinning', 'pinner', 'Pinner', 'cert', 'Cert', 'ssl', 'SSL', 'TLS', 'tls'];
        
        classNames.forEach(function(className) {
            validationKeywords.forEach(function(keyword) {
                if (className.indexOf(keyword) !== -1) {
                    try {
                        var clazz = ObjC.classes[className];
                        var methods = clazz.$ownMethods;
                        
                        methods.forEach(function(method) {
                            if (method.indexOf('verify') !== -1 || 
                                method.indexOf('Verify') !== -1 ||
                                method.indexOf('validate') !== -1 ||
                                method.indexOf('Validate') !== -1 ||
                                method.indexOf('trust') !== -1 ||
                                method.indexOf('Trust') !== -1) {
                                
                                try {
                                    Interceptor.attach(clazz[method].implementation, {
                                        onLeave: function(retval) {
                                            // Try to force success
                                            var orig = retval.toString();
                                            if (orig === '0x0') {
                                                retval.replace(ptr(0x1));
                                                console.log("[*] Forced " + className + " " + method + " to return YES");
                                            }
                                        }
                                    });
                                } catch(e) {}
                            }
                        });
                    } catch(e) {}
                }
            });
        });

        // ============================
        // FINAL STATUS
        // ============================
        
        console.log("[+] ================================");
        console.log("[+] SSL Pinning Bypass ACTIVE");
        console.log("[+] Proxy: " + proxyHost + ":" + proxyPort);
        console.log("[+] All major pinning methods hooked");
        console.log("[+] Traffic should appear in HTTP Toolkit");
        console.log("[+] ================================");
        
    } catch(err) {
        console.log("[!] Error: " + err.message);
        console.log(err.stack);
    }
} else {
    console.log("[!] Objective-C runtime not available");
}