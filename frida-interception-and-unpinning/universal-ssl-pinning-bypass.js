// Universal SSL Pinning Bypass for iOS
// Works with most iOS apps

console.log("[*] Starting Universal SSL Pinning Bypass...");

// Hook common SSL pinning methods
if (ObjC.available) {
    try {
        // NSURLSession bypass
        var className = "NSURLSession";
        var funcName = "- URLSession:didReceiveChallenge:completionHandler:";
        
        var hook = ObjC.classes.NSURLSession["- URLSession:didReceiveChallenge:completionHandler:"];
        if (hook) {
            Interceptor.attach(hook.implementation, {
                onEnter: function(args) {
                    console.log("[*] Bypassing SSL pinning in NSURLSession");
                    // Call completion handler to accept any certificate
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
                Memory.writePointer(error, NULL);
                return 1; // true
            }, 'bool', ['pointer', 'pointer']));
        }
        
        console.log("[+] SSL Pinning bypass hooks installed");
        
    } catch(err) {
        console.log("[!] Error setting up SSL pinning bypass: " + err.message);
    }
} else {
    console.log("[!] Objective-C runtime not available");
}

// Proxy configuration
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

console.log("[*] Proxy configured: " + proxyHost + ":" + proxyPort);
console.log("[+] Ready to intercept traffic!");
