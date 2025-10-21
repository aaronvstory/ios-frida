// Minimal Safe Bypass - Only handles the 403 error without crashing
console.log("[SAFE-BYPASS] Starting minimal safe bypass...");

if (ObjC.available) {
    // Only hook the specific problematic endpoint
    try {
        var NSURLSession = ObjC.classes.NSURLSession;

        // Hook dataTaskWithRequest
        var dataTaskMethod = NSURLSession['- dataTaskWithRequest:completionHandler:'];
        if (dataTaskMethod) {
            Interceptor.attach(dataTaskMethod.implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL().absoluteString().toString();

                    // Only intercept the specific failing endpoint
                    if (url.includes('/v1/dashes/') && url.includes('expand=vehicle')) {
                        console.log("[SAFE-BYPASS] Found problematic endpoint");

                        // Store for use in handler
                        this.isDashRequest = true;
                        this.url = url;

                        if (args[3]) {
                            var handler = new ObjC.Block(args[3]);
                            var origImpl = handler.implementation;

                            handler.implementation = function(data, response, error) {
                                console.log("[SAFE-BYPASS] Processing response");

                                // Check if we got a 403
                                if (response) {
                                    var httpResponse = new ObjC.Object(response);
                                    var statusCode = httpResponse.statusCode();

                                    if (statusCode == 403) {
                                        console.log("[SAFE-BYPASS] Got 403, returning empty success");

                                        // Return empty array (valid response)
                                        var emptyArray = "[]";
                                        var successData = ObjC.classes.NSString.stringWithString_(emptyArray).dataUsingEncoding_(4);

                                        // Create 200 response
                                        var newResponse = ObjC.classes.NSHTTPURLResponse.alloc().initWithURL_statusCode_HTTPVersion_headerFields_(
                                            httpResponse.URL(),
                                            200,
                                            ObjC.classes.NSString.stringWithString_("HTTP/1.1"),
                                            httpResponse.allHeaderFields()
                                        );

                                        // Return modified response
                                        return origImpl(successData, newResponse, null);
                                    }
                                }

                                // Pass through all other responses unchanged
                                return origImpl(data, response, error);
                            };
                        }
                    }
                }
            });
            console.log("[SAFE-BYPASS] Network hook installed");
        }
    } catch(e) {
        console.log("[SAFE-BYPASS] Hook error: " + e);
    }

    // Basic iOS spoofing (safe)
    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function(retval) {
                retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
            }
        });
        console.log("[SAFE-BYPASS] iOS spoofed to 17.6.1");
    } catch(e) {}

    console.log("[SAFE-BYPASS] Ready - minimal hooks active");

} else {
    console.log("[SAFE-BYPASS] ObjC not available!");
}