// Universal SSL Pinning Bypass with Proxy Configuration
// Works with most iOS apps and routes traffic through HTTP Toolkit

console.log("[*] Starting Universal SSL Pinning Bypass with Proxy...");

// Proxy configuration
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

// Hook NSURLSession to configure proxy
if (ObjC.available) {
    try {
        // Hook NSURLSessionConfiguration to set proxy
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        
        Interceptor.attach(NSURLSessionConfiguration['+ defaultSessionConfiguration'].implementation, {
            onLeave: function(retval) {
                console.log("[*] Configuring proxy for defaultSessionConfiguration");
                var config = new ObjC.Object(retval);
                
                // Create proxy dictionary - ONLY for HTTP/HTTPS, not DNS!
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
                proxyDict.setObject_forKey_(exceptionsArray, "ExceptionsList");
                
                // IMPORTANT: Exclude local/system from proxy to prevent DNS issues
                var exceptionsArray = ObjC.classes.NSMutableArray.alloc().init();
                exceptionsArray.addObject_("*.local");
                exceptionsArray.addObject_("localhost");
                proxyDict.setObject_forKey_(exceptionsArray, "ExceptionsList");
                
                config.setConnectionProxyDictionary_(proxyDict);
                console.log("[+] Proxy configured: " + proxyHost + ":" + proxyPort);
            }
        });
        
        Interceptor.attach(NSURLSessionConfiguration['+ ephemeralSessionConfiguration'].implementation, {
            onLeave: function(retval) {
                console.log("[*] Configuring proxy for ephemeralSessionConfiguration");
                var config = new ObjC.Object(retval);
                
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
                proxyDict.setObject_forKey_(exceptionsArray, "ExceptionsList");
                
                config.setConnectionProxyDictionary_(proxyDict);
            }
        });

        // SSL Pinning Bypass
        // Hook NSURLSession delegate methods
        var className = "NSURLSession";
        var funcName = "- URLSession:didReceiveChallenge:completionHandler:";
        
        var hook = ObjC.classes.NSURLSession["- URLSession:didReceiveChallenge:completionHandler:"];
        if (hook) {
            Interceptor.attach(hook.implementation, {
                onEnter: function(args) {
                    console.log("[*] Bypassing SSL pinning in NSURLSession");
                    var completionHandler = new ObjC.Block(args[4]);
                    completionHandler(0, null);
                }
            });
        }
        
        // SecTrustEvaluate bypass
        var SecTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                console.log("[*] Bypassing SecTrustEvaluate");
                Memory.writeU32(result, 0); // kSecTrustResultProceed
                return 0;
            }, 'int', ['pointer', 'pointer']));
        }
        
        // SecTrustEvaluateWithError bypass  
        var SecTrustEvaluateWithError = Module.findExportByName(null, "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                console.log("[*] Bypassing SecTrustEvaluateWithError");
                if (error !== 0) {
                    Memory.writePointer(error, ptr(0));
                }
                return 1; // true
            }, 'bool', ['pointer', 'pointer']));
        }

        // AFNetworking SSL pinning bypass
        try {
            var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
            Interceptor.attach(AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0x1);
                    console.log("[*] AFNetworking: setAllowInvalidCertificates = true");
                }
            });
            
            Interceptor.attach(AFSecurityPolicy['- allowInvalidCertificates'].implementation, {
                onLeave: function(retval) {
                    retval.replace(ptr(0x1));
                    console.log("[*] AFNetworking: allowInvalidCertificates = true");
                }
            });
        } catch(err) {
            // AFNetworking might not be present
        }

        console.log("[+] SSL Pinning bypass hooks installed");
        console.log("[+] Proxy routing configured");
        console.log("[+] Ready to intercept traffic!");
        
    } catch(err) {
        console.log("[!] Error setting up SSL pinning bypass: " + err.message);
    }
} else {
    console.log("[!] Objective-C runtime not available");
}