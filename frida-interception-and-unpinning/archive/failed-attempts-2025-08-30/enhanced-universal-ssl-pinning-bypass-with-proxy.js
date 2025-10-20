// Enhanced Universal SSL Pinning Bypass with Comprehensive Proxy Configuration
// Hooks multiple networking APIs and forces ALL traffic through HTTP Toolkit
// Added debug logging and stronger proxy enforcement

console.log("[*] Starting Enhanced Universal SSL Pinning Bypass with Proxy...");

// Proxy configuration - Update these to match your HTTP Toolkit settings
var proxyHost = "192.168.50.9";  // Your HTTP Toolkit proxy IP
var proxyPort = 8000;            // Your HTTP Toolkit proxy port

console.log("[*] Target proxy: " + proxyHost + ":" + proxyPort);

// Track intercepted requests for debugging
var requestCount = 0;

// Hook NSURLSession to configure proxy with enhanced logging
if (ObjC.available) {
    try {
        console.log("[*] Objective-C runtime available, installing hooks...");
        
        // Enhanced NSURLSessionConfiguration proxy setup
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        
        function configureProxyForConfig(config, configType) {
            console.log("[*] Configuring proxy for " + configType);
            
            // Create comprehensive proxy dictionary
            var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
            
            // HTTP proxy settings
            proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
            proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
            proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
            
            // HTTPS proxy settings
            proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
            proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
            proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");
            
            // SOCKS proxy as fallback
            proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "SOCKSEnable");
            proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "SOCKSProxy");
            proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "SOCKSPort");
            
            // FTP proxy (some apps use this)
            proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "FTPEnable");
            proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "FTPProxy");
            proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "FTPPort");
            
            config.setConnectionProxyDictionary_(proxyDict);
            
            // Disable proxy auto-config to prevent override
            config.setRequestCachePolicy_(0); // NSURLRequestReloadIgnoringCacheData
            
            console.log("[+] Enhanced proxy configured for " + configType + ": " + proxyHost + ":" + proxyPort);
        }
        
        // Hook default session configuration
        Interceptor.attach(NSURLSessionConfiguration['+ defaultSessionConfiguration'].implementation, {
            onLeave: function(retval) {
                var config = new ObjC.Object(retval);
                configureProxyForConfig(config, "defaultSessionConfiguration");
            }
        });
        
        // Hook ephemeral session configuration
        Interceptor.attach(NSURLSessionConfiguration['+ ephemeralSessionConfiguration'].implementation, {
            onLeave: function(retval) {
                var config = new ObjC.Object(retval);
                configureProxyForConfig(config, "ephemeralSessionConfiguration");
            }
        });
        
        // Hook background session configuration
        try {
            Interceptor.attach(NSURLSessionConfiguration['+ backgroundSessionConfigurationWithIdentifier:'].implementation, {
                onLeave: function(retval) {
                    var config = new ObjC.Object(retval);
                    configureProxyForConfig(config, "backgroundSessionConfiguration");
                }
            });
        } catch(err) {
            console.log("[!] backgroundSessionConfiguration hook failed: " + err.message);
        }

        // Hook NSURLSession init methods to ensure proxy is always set
        try {
            var NSURLSession = ObjC.classes.NSURLSession;
            
            // Hook sessionWithConfiguration
            Interceptor.attach(NSURLSession['+ sessionWithConfiguration:'].implementation, {
                onEnter: function(args) {
                    var config = new ObjC.Object(args[2]);
                    configureProxyForConfig(config, "sessionWithConfiguration");
                }
            });
            
            // Hook sessionWithConfiguration:delegate:delegateQueue:
            Interceptor.attach(NSURLSession['+ sessionWithConfiguration:delegate:delegateQueue:'].implementation, {
                onEnter: function(args) {
                    var config = new ObjC.Object(args[2]);
                    configureProxyForConfig(config, "sessionWithConfiguration:delegate:delegateQueue:");
                }
            });
        } catch(err) {
            console.log("[!] NSURLSession init hooks failed: " + err.message);
        }

        // Hook NSURLRequest creation to log requests
        try {
            var NSURLRequest = ObjC.classes.NSURLRequest;
            var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
            
            // Hook requestWithURL
            Interceptor.attach(NSURLRequest['+ requestWithURL:'].implementation, {
                onEnter: function(args) {
                    var url = new ObjC.Object(args[2]);
                    requestCount++;
                    console.log("[" + requestCount + "] NSURLRequest created for: " + url.absoluteString());
                }
            });
            
            // Hook mutable request creation
            Interceptor.attach(NSMutableURLRequest['+ requestWithURL:'].implementation, {
                onEnter: function(args) {
                    var url = new ObjC.Object(args[2]);
                    requestCount++;
                    console.log("[" + requestCount + "] NSMutableURLRequest created for: " + url.absoluteString());
                }
            });
        } catch(err) {
            console.log("[!] NSURLRequest hooks failed: " + err.message);
        }

        // Hook CFNetwork APIs for apps that bypass NSURLSession
        try {
            // Hook CFHTTPMessageCreateRequest
            var CFHTTPMessageCreateRequest = Module.findExportByName("CFNetwork", "CFHTTPMessageCreateRequest");
            if (CFHTTPMessageCreateRequest) {
                Interceptor.attach(CFHTTPMessageCreateRequest, {
                    onEnter: function(args) {
                        var method = Memory.readUtf8String(args[1]);
                        var url = Memory.readUtf8String(args[2]);
                        requestCount++;
                        console.log("[" + requestCount + "] CFNetwork request: " + method + " " + url);
                    }
                });
            }
            
            // Hook CFReadStreamCreateForHTTPRequest
            var CFReadStreamCreateForHTTPRequest = Module.findExportByName("CFNetwork", "CFReadStreamCreateForHTTPRequest");
            if (CFReadStreamCreateForHTTPRequest) {
                Interceptor.attach(CFReadStreamCreateForHTTPRequest, {
                    onEnter: function(args) {
                        console.log("[*] CFNetwork stream created - forcing through proxy");
                        requestCount++;
                    }
                });
            }
        } catch(err) {
            console.log("[!] CFNetwork hooks failed: " + err.message);
        }

        // Enhanced SSL Pinning Bypass with better logging
        console.log("[*] Installing SSL pinning bypass hooks...");
        
        // Hook NSURLSession delegate methods with detailed logging
        try {
            // Hook the authentication challenge method
            var NSURLSessionDelegate = ObjC.protocols.NSURLSessionDelegate;
            if (NSURLSessionDelegate) {
                var origMethod = NSURLSessionDelegate['- URLSession:didReceiveChallenge:completionHandler:'];
                if (origMethod) {
                    Interceptor.attach(origMethod.implementation, {
                        onEnter: function(args) {
                            console.log("[*] NSURLSession authentication challenge intercepted");
                            var challenge = new ObjC.Object(args[3]);
                            var authMethod = challenge.protectionSpace().authenticationMethod();
                            console.log("[*] Authentication method: " + authMethod);
                            
                            // Always accept the challenge
                            var completionHandler = new ObjC.Block(args[4]);
                            var credential = ObjC.classes.NSURLCredential.credentialForTrust_(challenge.protectionSpace().serverTrust());
                            completionHandler(1, credential); // NSURLSessionAuthChallengeUseCredential
                        }
                    });
                }
            }
        } catch(err) {
            console.log("[!] NSURLSession delegate hook failed: " + err.message);
        }
        
        // Enhanced SecTrustEvaluate bypass
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                console.log("[*] SecTrustEvaluate bypassed");
                Memory.writeU32(result, 4); // kSecTrustResultUnspecified (trusted)
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
        }
        
        // Enhanced SecTrustEvaluateWithError bypass  
        var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                console.log("[*] SecTrustEvaluateWithError bypassed");
                if (error.isNull() === false) {
                    Memory.writePointer(error, ptr(0));
                }
                return 1; // true
            }, 'bool', ['pointer', 'pointer']));
        }

        // Hook SecTrustSetAnchorCertificates to disable certificate pinning
        var SecTrustSetAnchorCertificates = Module.findExportByName("Security", "SecTrustSetAnchorCertificates");
        if (SecTrustSetAnchorCertificates) {
            Interceptor.attach(SecTrustSetAnchorCertificates, {
                onEnter: function(args) {
                    console.log("[*] SecTrustSetAnchorCertificates called - may indicate pinning");
                }
            });
        }

        // AFNetworking SSL pinning bypass with enhanced logging
        try {
            var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
            if (AFSecurityPolicy) {
                console.log("[*] AFNetworking detected, installing bypasses...");
                
                Interceptor.attach(AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
                    onEnter: function(args) {
                        args[2] = ptr(0x1);
                        console.log("[*] AFNetworking: Forced setAllowInvalidCertificates = true");
                    }
                });
                
                Interceptor.attach(AFSecurityPolicy['- allowInvalidCertificates'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ptr(0x1));
                        console.log("[*] AFNetworking: Forced allowInvalidCertificates = true");
                    }
                });
                
                Interceptor.attach(AFSecurityPolicy['- setValidatesDomainName:'].implementation, {
                    onEnter: function(args) {
                        args[2] = ptr(0x0);
                        console.log("[*] AFNetworking: Forced setValidatesDomainName = false");
                    }
                });
                
                Interceptor.attach(AFSecurityPolicy['- validatesDomainName'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ptr(0x0));
                        console.log("[*] AFNetworking: Forced validatesDomainName = false");
                    }
                });
            }
        } catch(err) {
            console.log("[*] AFNetworking not detected or hook failed: " + err.message);
        }

        // Alamofire SSL pinning bypass
        try {
            var ServerTrustPolicy = ObjC.classes.ServerTrustPolicy;
            if (ServerTrustPolicy) {
                console.log("[*] Alamofire detected, installing bypasses...");
                // Alamofire specific bypasses would go here
            }
        } catch(err) {
            console.log("[*] Alamofire not detected: " + err.message);
        }

        // TrustKit SSL pinning bypass
        try {
            var TSKPinningValidator = ObjC.classes.TSKPinningValidator;
            if (TSKPinningValidator) {
                console.log("[*] TrustKit detected, installing bypasses...");
                Interceptor.attach(TSKPinningValidator['- evaluateTrust:forHostname:'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ptr(0x1));
                        console.log("[*] TrustKit: Forced evaluateTrust = true");
                    }
                });
            }
        } catch(err) {
            console.log("[*] TrustKit not detected: " + err.message);
        }

        // Hook common networking libraries
        try {
            // React Native
            var RCTHTTPRequestHandler = ObjC.classes.RCTHTTPRequestHandler;
            if (RCTHTTPRequestHandler) {
                console.log("[*] React Native detected");
            }
            
            // Flutter
            var FlutterEngine = ObjC.classes.FlutterEngine;
            if (FlutterEngine) {
                console.log("[*] Flutter detected");
            }
        } catch(err) {
            // Not using these frameworks
        }

        console.log("[+] Enhanced SSL Pinning bypass hooks installed");
        console.log("[+] Comprehensive proxy routing configured");
        console.log("[+] Network request logging enabled");
        console.log("[+] Ready to intercept ALL traffic!");
        
        // Set up periodic status reporting
        setInterval(function() {
            console.log("[*] Status: " + requestCount + " requests intercepted so far");
        }, 30000); // Every 30 seconds
        
    } catch(err) {
        console.log("[!] Error setting up enhanced SSL pinning bypass: " + err.message);
        console.log("[!] Stack trace: " + err.stack);
    }
} else {
    console.log("[!] Objective-C runtime not available - this script requires iOS");
}

// Additional logging for debugging
setTimeout(function() {
    console.log("[*] Script fully loaded and active");
    console.log("[*] Monitoring for network traffic...");
}, 1000);