// EMERGENCY FIX - SSL Bypass without breaking DNS
console.log("[*] EMERGENCY FIX - SSL Bypass with selective proxy...");

// Proxy configuration - BUT NOT FOR EVERYTHING!
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

console.log("[*] Proxy: " + proxyHost + ":" + proxyPort + " (selective routing)");

if (ObjC.available) {
    try {
        // CRITICAL: SSL PINNING BYPASS FIRST
        console.log("[*] Installing SSL pinning bypass...");
        
        // Hook SecTrustEvaluate - MOST IMPORTANT
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                Memory.writeU32(result, 1); // kSecTrustResultProceed
                console.log("[+] SecTrustEvaluate bypassed");
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
        }
        
        // Hook SecTrustEvaluateWithError
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                console.log("[+] SecTrustEvaluateWithError bypassed");
                return 1; // true
            }, 'bool', ['pointer', 'pointer']));
        }
        
        // Hook SSLSetSessionOption
        var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
        if (SSLSetSessionOption) {
            Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
                return 0; // noErr
            }, 'int', ['pointer', 'int', 'bool']));
        }
        
        // Hook SSLHandshake
        var SSLHandshake = Module.findExportByName('Security', 'SSLHandshake'); 
        if (SSLHandshake) {
            Interceptor.replace(SSLHandshake, new NativeCallback(function(context) {
                return 0; // noErr
            }, 'int', ['pointer']));
        }
        
        // Hook tls_helper_create_peer_trust
        var tls_helper = Module.findExportByName('libnetwork.dylib', 'tls_helper_create_peer_trust');
        if (tls_helper) {
            Interceptor.replace(tls_helper, new NativeCallback(function() {
                return 0; // noErr
            }, 'int', []));
        }
        
        console.log("[+] SSL Pinning bypass complete!");
        
        // NOW handle proxy with SELECTIVE routing
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        
        function configureSelectiveProxy(config, configType) {
            try {
                // Get the current URL to decide if we should proxy
                var shouldProxy = true;
                
                // Create proxy dictionary ONLY for HTTP/HTTPS traffic
                var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
                
                // Only proxy HTTP/HTTPS, not DNS or other protocols
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");
                
                // CRITICAL: Exclude certain hosts from proxy to prevent DNS issues
                var exceptionsArray = ObjC.classes.NSMutableArray.alloc().init();
                exceptionsArray.addObject_("localhost");
                exceptionsArray.addObject_("127.0.0.1");
                exceptionsArray.addObject_("*.local");
                proxyDict.setObject_forKey_(exceptionsArray, "ExceptionsList");
                
                config.setConnectionProxyDictionary_(proxyDict);
                console.log("[+] Selective proxy configured for " + configType);
            } catch (e) {
                console.log("[!] Error configuring proxy: " + e);
            }
        }
        
        // Hook configuration methods
        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration'].forEach(function(method) {
            try {
                var origMethod = NSURLSessionConfiguration[method];
                if (origMethod) {
                    Interceptor.attach(origMethod.implementation, {
                        onLeave: function(retval) {
                            var config = new ObjC.Object(retval);
                            configureSelectiveProxy(config, method.replace('+ ', ''));
                        }
                    });
                }
            } catch (e) {}
        });
        
        // Also hook NSURLSession creation
        if (ObjC.classes.NSURLSession) {
            var sessionMethods = ['+ sessionWithConfiguration:', '+ sessionWithConfiguration:delegate:delegateQueue:'];
            sessionMethods.forEach(function(method) {
                try {
                    var origMethod = ObjC.classes.NSURLSession[method];
                    if (origMethod) {
                        Interceptor.attach(origMethod.implementation, {
                            onEnter: function(args) {
                                var config = new ObjC.Object(args[2]);
                                configureSelectiveProxy(config, 'sessionWithConfiguration');
                            }
                        });
                    }
                } catch (e) {}
            });
        }
        
        console.log("[+] Emergency fix applied!");
        console.log("[*] SSL bypassed, selective proxy active");
        console.log("[*] DNS should work now!");
        
    } catch (error) {
        console.log("[!] Error: " + error);
    }
}