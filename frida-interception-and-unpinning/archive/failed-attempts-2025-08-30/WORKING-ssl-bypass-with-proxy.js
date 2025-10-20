// WORKING SSL Bypass WITH Proxy - No DNS issues
console.log("[*] Starting WORKING SSL Bypass with HTTP Toolkit Proxy...");

// Proxy settings
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

console.log("[*] Proxy: " + proxyHost + ":" + proxyPort);

if (ObjC.available) {
    setTimeout(function() {
        // PART 1: SSL BYPASS
        console.log("[*] Installing SSL bypass hooks...");
        
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
        
        // PART 2: PROXY CONFIGURATION (Careful not to break DNS!)
        console.log("[*] Configuring proxy for HTTP/HTTPS only...");
        
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        
        function configureProxy(config) {
            try {
                var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
                
                // HTTP proxy
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
                
                // HTTPS proxy  
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");
                
                // IMPORTANT: Do NOT proxy other protocols
                // No SOCKS, no FTP, no DNS proxying!
                
                config.setConnectionProxyDictionary_(proxyDict);
                return true;
            } catch (e) {
                console.log("[!] Error setting proxy: " + e);
                return false;
            }
        }
        
        // Hook default configuration
        Interceptor.attach(NSURLSessionConfiguration['+ defaultSessionConfiguration'].implementation, {
            onLeave: function(retval) {
                var config = new ObjC.Object(retval);
                if (configureProxy(config)) {
                    console.log("[+] Proxy set for defaultSessionConfiguration");
                }
            }
        });
        
        // Hook ephemeral configuration
        Interceptor.attach(NSURLSessionConfiguration['+ ephemeralSessionConfiguration'].implementation, {
            onLeave: function(retval) {
                var config = new ObjC.Object(retval);
                if (configureProxy(config)) {
                    console.log("[+] Proxy set for ephemeralSessionConfiguration");
                }
            }
        });
        
        console.log("[+] Setup complete!");
        console.log("[*] SSL bypassed, HTTP/HTTPS proxy active");
        console.log("[*] DNS resolution should work normally");
        
    }, 100);
}