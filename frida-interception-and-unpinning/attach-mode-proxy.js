// Attach Mode Proxy Script - Specialized for attaching to running apps
// Works better when the app is already initialized

console.log("[*] Attach Mode Proxy Script Starting...");

var proxyHost = "192.168.50.9";
var proxyPort = 8000;

console.log("[*] Configuring proxy: " + proxyHost + ":" + proxyPort);

if (ObjC.available) {
    // Wait a bit for the app to stabilize
    setTimeout(function() {
        console.log("[*] Injecting proxy configuration into existing sessions...");
        
        // Find and modify ALL existing NSURLSession instances
        ObjC.choose(ObjC.classes.NSURLSession, {
            onMatch: function(session) {
                try {
                    var config = session.configuration();
                    if (config) {
                        console.log("[*] Found existing session, updating proxy...");
                        
                        var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
                        proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                        proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
                        proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
                        proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                        proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
                        proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");
                        
                        config.setConnectionProxyDictionary_(proxyDict);
                        console.log("[+] Updated existing session with proxy");
                    }
                } catch (e) {
                    console.log("[!] Error updating session: " + e);
                }
            },
            onComplete: function() {
                console.log("[*] Finished updating existing sessions");
            }
        });
        
        // Also hook future session creations
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        
        // Replace the shared/default configurations
        try {
            var sharedSession = ObjC.classes.NSURLSession.sharedSession();
            if (sharedSession) {
                var config = sharedSession.configuration();
                var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");
                
                config.setConnectionProxyDictionary_(proxyDict);
                console.log("[+] Updated sharedSession configuration");
            }
        } catch (e) {
            console.log("[!] Could not update shared session: " + e);
        }
        
        // Hook configuration methods for new sessions
        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration'].forEach(function(method) {
            try {
                var origMethod = NSURLSessionConfiguration[method];
                if (origMethod) {
                    Interceptor.attach(origMethod.implementation, {
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
                            console.log("[+] Hooked new " + method.replace('+ ', ''));
                        }
                    });
                }
            } catch (e) {
                // Ignore
            }
        });
        
        // SSL Bypass
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                Memory.writeU32(result, 1);
                return 0;
            }, 'int', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluate bypassed");
        }
        
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                return 1;
            }, 'bool', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluateWithError bypassed");
        }
        
        console.log("[+] Attach mode proxy configuration complete!");
        console.log("[*] Trigger a new network request in the app to test...");
        
    }, 1000); // Wait 1 second before modifying
}