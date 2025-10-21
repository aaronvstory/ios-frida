// Perfect Bypass - Handles both 403 and RequestProcessingError
console.log("[PERFECT-BYPASS] Starting comprehensive bypass...");

if (ObjC.available) {
    var bypassCount = 0;

    // =========================
    // MAIN BYPASS: Network Response Handler
    // =========================
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        var NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
        var NSString = ObjC.classes.NSString;

        // Hook the main dataTask method
        var dataTaskMethod = NSURLSession['- dataTaskWithRequest:completionHandler:'];
        if (dataTaskMethod) {
            Interceptor.attach(dataTaskMethod.implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL().absoluteString().toString();

                    // Check for dash endpoints
                    if (url.includes('/dashes') || url.includes('/dash/')) {
                        console.log("[PERFECT-BYPASS] Intercepting: " + url.substring(0, 100) + "...");

                        // Store original handler
                        this.url = url;
                        this.request = request;

                        // Modify completion handler
                        if (args[3]) {
                            var handler = new ObjC.Block(args[3]);
                            var origImpl = handler.implementation;

                            handler.implementation = function(data, response, error) {
                                // Always return success for dash endpoints
                                console.log("[PERFECT-BYPASS] Hijacking response for dash endpoint");

                                // Create proper success response based on URL
                                var successData;

                                if (url.includes('/v1/dashes')) {
                                    // For GET /v1/dashes - return empty list
                                    successData = [];
                                } else if (url.includes('/v3/dasher/me/dashes')) {
                                    // For v3 endpoint - return proper structure
                                    successData = {
                                        "dashes": [],
                                        "active_dash": null,
                                        "next_dash": null
                                    };
                                } else {
                                    // Generic success
                                    successData = {"success": true};
                                }

                                // Convert to NSData
                                var jsonStr = JSON.stringify(successData);
                                var newData = NSString.stringWithString_(jsonStr).dataUsingEncoding_(4);

                                // Create success response
                                var newResponse = NSHTTPURLResponse.alloc().initWithURL_statusCode_HTTPVersion_headerFields_(
                                    request.URL(),
                                    200,
                                    NSString.stringWithString_("HTTP/1.1"),
                                    ObjC.classes.NSDictionary.dictionaryWithObject_forKey_(
                                        NSString.stringWithString_("application/json"),
                                        NSString.stringWithString_("Content-Type")
                                    )
                                );

                                console.log("[PERFECT-BYPASS] Returning success with data: " + jsonStr.substring(0, 100));

                                // Return success with no error
                                return origImpl(newData, newResponse, null);
                            };
                        }
                    }
                }
            });
            console.log("[PERFECT-BYPASS] Network interception installed");
        }

    } catch(e) {
        console.log("[PERFECT-BYPASS] Network hook error: " + e);
    }

    // =========================
    // ERROR PREVENTION
    // =========================
    try {
        var NSError = ObjC.classes.NSError;

        // Block error creation
        Interceptor.attach(NSError['+ errorWithDomain:code:userInfo:'].implementation, {
            onEnter: function(args) {
                var domain = new ObjC.Object(args[2]).toString();
                var code = args[3].toInt32();

                if (domain.includes('ErrorNetworking') || domain.includes('DoorDash')) {
                    console.log("[PERFECT-BYPASS] Preventing error: " + domain + " code: " + code);
                    // Return a benign error instead
                    args[2] = NSString.stringWithString_("NSCocoaErrorDomain");
                    args[3] = ptr(0);
                }
            }
        });

        console.log("[PERFECT-BYPASS] Error prevention installed");

    } catch(e) {
        console.log("[PERFECT-BYPASS] Error hook failed: " + e);
    }

    // =========================
    // ALERT SUPPRESSION (FIXED)
    // =========================
    try {
        var UIAlertController = ObjC.classes.UIAlertController;

        // Hook alert creation
        var alertMethod = UIAlertController['+ alertControllerWithTitle:message:preferredStyle:'];
        if (alertMethod) {
            Interceptor.attach(alertMethod.implementation, {
                onEnter: function(args) {
                    // Check if args[2] and args[3] are valid objects
                    if (args[2] && !args[2].isNull()) {
                        var title = new ObjC.Object(args[2]);
                        var titleStr = title.toString();

                        if (titleStr.includes('Error') || titleStr.includes('error')) {
                            console.log("[PERFECT-BYPASS] Blocking error alert: " + titleStr);
                            // Replace with empty strings
                            args[2] = NSString.stringWithString_("");
                            args[3] = NSString.stringWithString_("");
                        }
                    }

                    if (args[3] && !args[3].isNull()) {
                        var message = new ObjC.Object(args[3]);
                        var msgStr = message.toString();

                        if (msgStr.includes('unable to start') || msgStr.includes('ErrorNetworking') ||
                            msgStr.includes('403') || msgStr.includes('try again')) {
                            console.log("[PERFECT-BYPASS] Blocking error message: " + msgStr.substring(0, 50));
                            // Replace with empty strings
                            args[2] = NSString.stringWithString_("");
                            args[3] = NSString.stringWithString_("");
                        }
                    }
                }
            });
        }

        console.log("[PERFECT-BYPASS] Alert suppression installed");

    } catch(e) {
        console.log("[PERFECT-BYPASS] Alert hook error: " + e);
    }

    // =========================
    // VIEW CONTROLLER PRESENTATION BLOCK
    // =========================
    try {
        var UIViewController = ObjC.classes.UIViewController;

        // Block presentation of error view controllers
        var presentMethod = UIViewController['- presentViewController:animated:completion:'];
        if (presentMethod) {
            Interceptor.attach(presentMethod.implementation, {
                onEnter: function(args) {
                    var vc = new ObjC.Object(args[2]);

                    // Check if it's an alert controller
                    if (vc.isKindOfClass_(ObjC.classes.UIAlertController)) {
                        // Get title and message
                        try {
                            var title = vc.title();
                            var message = vc.message();

                            if (title || message) {
                                var titleStr = title ? title.toString() : "";
                                var msgStr = message ? message.toString() : "";

                                if (titleStr.includes('Error') || msgStr.includes('error') ||
                                    msgStr.includes('unable to start') || msgStr.includes('ErrorNetworking')) {

                                    console.log("[PERFECT-BYPASS] Blocking error presentation");

                                    // Prevent presentation by making it a no-op
                                    args[2] = null;
                                }
                            }
                        } catch(e) {}
                    }
                }
            });
        }

        console.log("[PERFECT-BYPASS] View controller block installed");

    } catch(e) {
        console.log("[PERFECT-BYPASS] VC hook error: " + e);
    }

    // =========================
    // iOS VERSION SPOOFING
    // =========================
    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function(retval) {
                retval.replace(NSString.stringWithString_("17.6.1"));
            }
        });
        console.log("[PERFECT-BYPASS] iOS spoofed to 17.6.1");
    } catch(e) {}

    // =========================
    // SUMMARY
    // =========================
    console.log("\n" + "=".repeat(60));
    console.log("PERFECT BYPASS ACTIVE");
    console.log("=".repeat(60));
    console.log("✓ Network requests intercepted");
    console.log("✓ Error prevention active");
    console.log("✓ Alert suppression fixed");
    console.log("✓ View controller blocking");
    console.log("✓ iOS version spoofed");
    console.log("=".repeat(60));
    console.log("Tap 'Schedule/Dash Now' - should work now!");
    console.log("=".repeat(60) + "\n");

} else {
    console.log("[PERFECT-BYPASS] ObjC not available!");
}