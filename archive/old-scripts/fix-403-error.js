// Fix for DoorDash Dasher 403 Error
// Intercepts the failing /v1/dashes/ request and provides a success response

console.log("[FIX-403] Starting 403 error bypass...");

if (ObjC.available) {
    // Hook NSURLSession to intercept the problematic request
    var NSURLSession = ObjC.classes.NSURLSession;

    // Hook dataTaskWithRequest
    var dataTaskMethod = NSURLSession['- dataTaskWithRequest:completionHandler:'];
    if (dataTaskMethod) {
        Interceptor.attach(dataTaskMethod.implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();

                // Check if this is the problematic dashes request
                if (url.includes('/v1/dashes/') && url.includes('expand=vehicle')) {
                    console.log("[FIX-403] Intercepting problematic request: " + url);

                    // Get the original completion handler
                    var handler = new ObjC.Block(args[3]);
                    var originalImpl = handler.implementation;

                    // Replace with our modified handler
                    handler.implementation = function(data, response, error) {
                        console.log("[FIX-403] Original response received");

                        if (response) {
                            var httpResponse = new ObjC.Object(response);
                            var statusCode = httpResponse.statusCode();

                            if (statusCode == 403) {
                                console.log("[FIX-403] Got 403 error - replacing with success response");

                                // Create a successful response with an empty dash list
                                var successData = {
                                    "dashes": [],
                                    "active_dash": null,
                                    "can_dash": true,
                                    "eligible_to_dash": true,
                                    "shift_available": true
                                };

                                // Convert to NSData
                                var jsonStr = JSON.stringify(successData);
                                var successDataObj = ObjC.classes.NSString.stringWithString_(jsonStr).dataUsingEncoding_(4);

                                // Create a new 200 response
                                var NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
                                var newResponse = NSHTTPURLResponse.alloc().initWithURL_statusCode_HTTPVersion_headerFields_(
                                    httpResponse.URL(),
                                    200,
                                    ObjC.classes.NSString.stringWithString_("HTTP/1.1"),
                                    httpResponse.allHeaderFields()
                                );

                                console.log("[FIX-403] Returning modified 200 response");

                                // Call original handler with modified response
                                return originalImpl(successDataObj, newResponse, null);
                            }
                        }

                        // For all other cases, pass through unchanged
                        return originalImpl(data, response, error);
                    };
                }
            }
        });
        console.log("[FIX-403] Hook installed for /v1/dashes/ endpoint");
    }

    // Also hook the POST request that creates a dash
    try {
        Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();
                var method = request.HTTPMethod() ? request.HTTPMethod().toString() : 'GET';

                // Check for POST to dashes endpoint
                if (method === 'POST' && url.includes('/v1/dashes')) {
                    console.log("[FIX-403] Intercepting POST to dashes");

                    var handler = new ObjC.Block(args[3]);
                    var originalImpl = handler.implementation;

                    handler.implementation = function(data, response, error) {
                        if (response) {
                            var httpResponse = new ObjC.Object(response);
                            var statusCode = httpResponse.statusCode();

                            if (statusCode >= 400) {
                                console.log("[FIX-403] POST failed with status " + statusCode + " - creating fake success");

                                // Create a fake dash response
                                var dashData = {
                                    "id": "fake-dash-" + Date.now(),
                                    "status": "active",
                                    "start_time": new Date().toISOString(),
                                    "end_time": new Date(Date.now() + 3600000).toISOString(),
                                    "starting_point": {
                                        "id": 1,
                                        "name": "Current Location"
                                    },
                                    "vehicle": {
                                        "id": 1,
                                        "type": "car"
                                    }
                                };

                                var jsonStr = JSON.stringify(dashData);
                                var successData = ObjC.classes.NSString.stringWithString_(jsonStr).dataUsingEncoding_(4);

                                var newResponse = ObjC.classes.NSHTTPURLResponse.alloc().initWithURL_statusCode_HTTPVersion_headerFields_(
                                    httpResponse.URL(),
                                    201,
                                    ObjC.classes.NSString.stringWithString_("HTTP/1.1"),
                                    httpResponse.allHeaderFields()
                                );

                                console.log("[FIX-403] Returning fake dash creation success");
                                return originalImpl(successData, newResponse, null);
                            }
                        }

                        return originalImpl(data, response, error);
                    };
                }
            }
        });
    } catch(e) {
        console.log("[FIX-403] Error setting up POST hook: " + e);
    }

    // Basic iOS spoofing
    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function(retval) {
                retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
            }
        });
        console.log("[FIX-403] iOS spoofed to 17.6.1");
    } catch(e) {}

    console.log("\n========================================");
    console.log("403 ERROR FIX ACTIVE");
    console.log("The app should now bypass the dash error");
    console.log("========================================\n");

} else {
    console.log("[FIX-403] ObjC not available!");
}