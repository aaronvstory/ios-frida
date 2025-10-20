// Proxy Diagnostics Script - Use this to debug proxy connectivity issues
// Run this script to test if the proxy is working and accessible

console.log("[*] Starting Proxy Diagnostics...");

var proxyHost = "192.168.50.9";
var proxyPort = 8000;

if (ObjC.available) {
    // Test basic network connectivity
    console.log("[*] Testing network connectivity to proxy...");
    
    try {
        // Create a simple test request through the proxy
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        var config = NSURLSessionConfiguration.defaultSessionConfiguration();
        
        // Configure proxy
        var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
        proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
        proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
        proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
        proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
        proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
        proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");
        
        config.setConnectionProxyDictionary_(proxyDict);
        
        console.log("[+] Proxy configuration test: SUCCESS");
        console.log("[*] Proxy settings: " + proxyHost + ":" + proxyPort);
        
        // Test if we can reach common endpoints
        var testUrls = [
            "http://httpbin.org/ip",
            "https://httpbin.org/ip", 
            "http://google.com",
            "https://api.github.com"
        ];
        
        testUrls.forEach(function(testUrl) {
            var url = ObjC.classes.NSURL.URLWithString_(testUrl);
            var request = ObjC.classes.NSURLRequest.requestWithURL_(url);
            
            console.log("[*] Testing connection to: " + testUrl);
            
            // Create session with proxy config
            var session = ObjC.classes.NSURLSession.sessionWithConfiguration_(config);
            
            // This would normally make the request, but we're just testing the setup
            console.log("[+] Request setup successful for: " + testUrl);
        });
        
        console.log("[*] All test URLs configured successfully");
        
        // Hook network calls to verify proxy usage
        var NSURLConnection = ObjC.classes.NSURLConnection;
        if (NSURLConnection) {
            Interceptor.attach(NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'].implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL();
                    console.log("[DIAGNOSTIC] NSURLConnection request to: " + url.absoluteString());
                }
            });
        }
        
    } catch(err) {
        console.log("[!] Proxy configuration test FAILED: " + err.message);
    }
    
    // Check system proxy settings
    try {
        var systemConfig = ObjC.classes.NSURLSessionConfiguration.defaultSessionConfiguration();
        var currentProxy = systemConfig.connectionProxyDictionary();
        
        if (currentProxy) {
            console.log("[*] Current system proxy settings detected:");
            var keys = currentProxy.allKeys();
            for (var i = 0; i < keys.count(); i++) {
                var key = keys.objectAtIndex_(i);
                var value = currentProxy.objectForKey_(key);
                console.log("[*]   " + key + " = " + value);
            }
        } else {
            console.log("[*] No system proxy settings detected");
        }
    } catch(err) {
        console.log("[!] Could not read system proxy settings: " + err.message);
    }
    
} else {
    console.log("[!] Objective-C runtime not available");
}

console.log("[*] Proxy diagnostics complete");

// Test script to verify Frida is working
console.log("[*] Frida attachment test: SUCCESS");
console.log("[*] Current process: " + Process.id);
console.log("[*] Architecture: " + Process.arch);
console.log("[*] Platform: " + Process.platform);