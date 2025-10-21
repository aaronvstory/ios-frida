// Ultimate Dasher Monitor Script
// Captures EVERYTHING related to network and errors

console.log("[ULTIMATE] Monitor script starting...");

if (ObjC.available) {
    // Global storage for requests
    var requestMap = {};
    var requestCounter = 0;

    // ============ NETWORK MONITORING ============

    // Hook NSURLSession dataTaskWithRequest
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSURLRequest = ObjC.classes.NSMutableURLRequest;

    // Method 1: dataTaskWithRequest:completionHandler:
    try {
        var dataTaskMethod = NSURLSession['- dataTaskWithRequest:completionHandler:'];
        if (dataTaskMethod) {
            Interceptor.attach(dataTaskMethod.implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL().absoluteString().toString();
                    var method = request.HTTPMethod() ? request.HTTPMethod().toString() : 'GET';

                    requestCounter++;
                    var reqId = requestCounter;

                    console.log("\n[REQUEST #" + reqId + "] " + method + " " + url);

                    // Get headers
                    var headers = request.allHTTPHeaderFields();
                    if (headers) {
                        var headerObj = {};
                        var keys = headers.allKeys();
                        for (var i = 0; i < keys.count(); i++) {
                            var key = keys.objectAtIndex_(i).toString();
                            headerObj[key] = headers.objectForKey_(key).toString();
                        }
                        console.log("[HEADERS] " + JSON.stringify(headerObj));
                    }

                    // Get body
                    var body = request.HTTPBody();
                    if (body) {
                        try {
                            var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
                            if (bodyStr) {
                                console.log("[BODY] " + bodyStr.toString().substring(0, 500));
                            }
                        } catch(e) {}
                    }

                    // Store request info
                    requestMap[url] = reqId;

                    // Hook the completion handler
                    var handler = new ObjC.Block(args[3]);
                    var originalImpl = handler.implementation;

                    handler.implementation = function(data, response, error) {
                        var responseStr = "";
                        var statusCode = 0;

                        if (response) {
                            var resp = new ObjC.Object(response);
                            statusCode = resp.statusCode();

                            console.log("\n[RESPONSE #" + reqId + "] Status: " + statusCode + " for " + url);

                            // Get response body
                            if (data) {
                                try {
                                    var respBody = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                    if (respBody) {
                                        responseStr = respBody.toString();

                                        // Log errors in detail
                                        if (statusCode >= 400) {
                                            console.log("[ERROR RESPONSE] Status " + statusCode);
                                            console.log("[ERROR BODY] " + responseStr);

                                            // Look for specific error patterns
                                            if (responseStr.includes("ErrorNetworking") ||
                                                responseStr.includes("ResponseStatusCodeError")) {
                                                console.log("!!! FOUND THE ERROR: ErrorNetworking.ResponseStatusCodeError !!!");
                                                console.log("Full error details: " + responseStr);
                                            }
                                        } else {
                                            console.log("[RESPONSE BODY] " + responseStr.substring(0, 200) + "...");
                                        }
                                    }
                                } catch(e) {
                                    console.log("[RESPONSE] Binary data");
                                }
                            }
                        }

                        if (error) {
                            console.log("[NETWORK ERROR #" + reqId + "] " + error.localizedDescription().toString());
                        }

                        return originalImpl(data, response, error);
                    };
                }
            });
            console.log("[ULTIMATE] NSURLSession hooks installed");
        }
    } catch(e) {
        console.log("[ULTIMATE] NSURLSession hook error: " + e);
    }

    // ============ ERROR MONITORING ============

    // Hook NSError creation
    try {
        var NSError = ObjC.classes.NSError;
        Interceptor.attach(NSError['+ errorWithDomain:code:userInfo:'].implementation, {
            onEnter: function(args) {
                var domain = new ObjC.Object(args[2]).toString();
                var code = args[3].toInt32();
                var userInfo = new ObjC.Object(args[4]);

                if (domain.includes("DoorDash") || domain.includes("ErrorNetworking") ||
                    domain.includes("Dash") || code == 1) {
                    console.log("\n!!! NSError Created !!!");
                    console.log("Domain: " + domain);
                    console.log("Code: " + code);
                    if (userInfo) {
                        console.log("UserInfo: " + userInfo.toString());
                    }
                }
            }
        });
        console.log("[ULTIMATE] NSError monitoring installed");
    } catch(e) {
        console.log("[ULTIMATE] NSError hook error: " + e);
    }

    // ============ ANALYTICS MONITORING ============

    // Hook JSON serialization to see what's being sent
    try {
        var NSJSONSerialization = ObjC.classes.NSJSONSerialization;
        Interceptor.attach(NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
            onEnter: function(args) {
                var obj = new ObjC.Object(args[2]);
                var str = obj.toString();

                // Look for dash-related or version-related content
                if (str.includes("dash") || str.includes("shift") ||
                    str.includes("os_version") || str.includes("device_os")) {
                    console.log("[ANALYTICS] " + str.substring(0, 300));

                    // Check for version inconsistencies
                    if (str.includes("16.3.1")) {
                        console.log("!!! FOUND 16.3.1 in analytics !!!");
                    }
                }
            }
        });
        console.log("[ULTIMATE] Analytics monitoring installed");
    } catch(e) {
        console.log("[ULTIMATE] Analytics hook error: " + e);
    }

    // ============ BASIC iOS SPOOFING ============

    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function(retval) {
                retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
            }
        });
        console.log("[ULTIMATE] iOS spoofed to 17.6.1");
    } catch(e) {
        console.log("[ULTIMATE] Spoof error: " + e);
    }

    console.log("\n========================================");
    console.log("ULTIMATE MONITOR READY");
    console.log("Tap 'Dash Now' to capture the error");
    console.log("========================================\n");

} else {
    console.log("[ULTIMATE] ObjC not available!");
}