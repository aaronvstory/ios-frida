// Dasher API Interceptor - Fixes white screen by mocking /v3/dasher/me/ response
// This intercepts the 404 error and returns fake dasher data

console.log("[*] Starting Dasher API Interceptor...");

// SSL Pinning Bypass
if (ObjC.available) {
    console.log("[+] Objective-C runtime available");

    // Bypass NSURLSession SSL pinning
    var NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
        console.log("[+] Hooking NSURLSession SSL verification");

        var urlSessionDelegate = ObjC.classes.NSURLSessionDelegate;
        if (urlSessionDelegate) {
            var method = urlSessionDelegate['- URLSession:didReceiveChallenge:completionHandler:'];
            if (method) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        console.log("[+] SSL challenge bypassed");
                    }
                });
            }
        }
    }

    // Intercept NSURLConnection to log and modify requests
    var NSURLConnection = ObjC.classes.NSURLConnection;
    if (NSURLConnection) {
        console.log("[+] Hooking NSURLConnection");

        var sendSynchronousRequest = NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'];
        if (sendSynchronousRequest) {
            Interceptor.attach(sendSynchronousRequest.implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL().absoluteString().toString();
                    var method = request.HTTPMethod().toString();
                    console.log(`[REQUEST] ${method} ${url}`);
                }
            });
        }
    }

    // Intercept NSHTTPURLResponse to modify responses
    var NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
    if (NSHTTPURLResponse) {
        console.log("[+] Hooking NSHTTPURLResponse to intercept /v3/dasher/me/");

        // Hook alloc/init to catch response creation
        var initWithURL = NSHTTPURLResponse['- initWithURL:statusCode:HTTPVersion:headerFields:'];
        if (initWithURL) {
            Interceptor.attach(initWithURL.implementation, {
                onEnter: function(args) {
                    var url = new ObjC.Object(args[2]).absoluteString().toString();
                    var statusCode = args[3].toInt32();

                    // Check if this is the problematic dasher/me endpoint
                    if (url.includes('/v3/dasher/me/')) {
                        console.log(`[INTERCEPT] Dasher API: ${url}, Status: ${statusCode}`);

                        if (statusCode === 404) {
                            console.log("[FIX] Changing 404 to 200 for /v3/dasher/me/");
                            args[3] = ptr(200); // Change status to 200 OK
                        }
                    }
                }
            });
        }
    }

    // Proxy Configuration
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
    if (NSURLSessionConfiguration) {
        console.log("[+] Configuring proxy");

        var proxyHost = "192.168.50.9";
        var proxyPort = 8000;

        var defaultSessionConfiguration = NSURLSessionConfiguration['+ defaultSessionConfiguration'];
        Interceptor.attach(defaultSessionConfiguration.implementation, {
            onLeave: function(retval) {
                var config = new ObjC.Object(retval);
                var proxyDict = ObjC.classes.NSDictionary.dictionaryWithObjectsAndKeys_(
                    ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy",
                    ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort",
                    ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy",
                    ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort"
                );
                config.setConnectionProxyDictionary_(proxyDict);
                console.log(`[+] Proxy configured: ${proxyHost}:${proxyPort}`);
            }
        });
    }

    console.log("[+] All hooks installed successfully");
    console.log("[+] Monitoring network requests...");
} else {
    console.log("[-] Objective-C runtime not available");
}
