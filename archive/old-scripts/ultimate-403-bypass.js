// Ultimate 403 Bypass for DoorDash Dasher
// Intercepts at multiple levels to ensure success

console.log("[ULTIMATE-BYPASS] Initializing comprehensive 403 bypass...");

if (ObjC.available) {
    var bypassCount = 0;

    // =========================
    // METHOD 1: NSURLSession Response Modification
    // =========================
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        var NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
        var NSString = ObjC.classes.NSString;

        // Hook ALL dataTask methods
        var methods = [
            '- dataTaskWithRequest:completionHandler:',
            '- dataTaskWithURL:completionHandler:',
            '- dataTaskWithRequest:',
            '- dataTaskWithURL:'
        ];

        methods.forEach(function(methodName) {
            var method = NSURLSession[methodName];
            if (method) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        // Get request details
                        var request = new ObjC.Object(args[2]);
                        var url = "";

                        try {
                            if (request.URL) {
                                url = request.URL().absoluteString().toString();
                            } else if (request.absoluteString) {
                                url = request.absoluteString().toString();
                            }
                        } catch(e) {}

                        // Check if it's a dash-related endpoint
                        if (url.includes('/dashes') || url.includes('/dash/') || url.includes('schedule')) {
                            console.log("[ULTIMATE-BYPASS] Monitoring: " + url);

                            // Get completion handler if it exists
                            if (args[3]) {
                                var handler = new ObjC.Block(args[3]);
                                var origImpl = handler.implementation;

                                handler.implementation = function(data, response, error) {
                                    if (response) {
                                        var resp = new ObjC.Object(response);
                                        var status = resp.statusCode();

                                        if (status >= 400) {
                                            bypassCount++;
                                            console.log("[ULTIMATE-BYPASS] Intercepted error " + status + " - Bypass #" + bypassCount);

                                            // Create success response data
                                            var successObj = {
                                                "success": true,
                                                "dashes": [],
                                                "active_dash": {
                                                    "id": "bypass-" + Date.now(),
                                                    "status": "active",
                                                    "can_dash": true
                                                },
                                                "eligible_to_dash": true,
                                                "message": "Bypassed"
                                            };

                                            var jsonStr = JSON.stringify(successObj);
                                            var newData = NSString.stringWithString_(jsonStr).dataUsingEncoding_(4);

                                            // Create new 200 response
                                            var newResp = NSHTTPURLResponse.alloc().initWithURL_statusCode_HTTPVersion_headerFields_(
                                                resp.URL(),
                                                200,
                                                NSString.stringWithString_("HTTP/1.1"),
                                                resp.allHeaderFields()
                                            );

                                            console.log("[ULTIMATE-BYPASS] Returning fake success response");
                                            return origImpl(newData, newResp, null);
                                        }
                                    }

                                    // Check for network errors
                                    if (error && url.includes('/dashes')) {
                                        console.log("[ULTIMATE-BYPASS] Network error detected, creating fake success");

                                        var successObj = {"success": true, "message": "Bypass active"};
                                        var jsonStr = JSON.stringify(successObj);
                                        var newData = NSString.stringWithString_(jsonStr).dataUsingEncoding_(4);

                                        // Create fake response
                                        var fakeResp = NSHTTPURLResponse.alloc().initWithURL_statusCode_HTTPVersion_headerFields_(
                                            request.URL(),
                                            200,
                                            NSString.stringWithString_("HTTP/1.1"),
                                            null
                                        );

                                        return origImpl(newData, fakeResp, null);
                                    }

                                    return origImpl(data, response, error);
                                };
                            }
                        }
                    }
                });
                console.log("[ULTIMATE-BYPASS] Hooked " + methodName);
            }
        });

    } catch(e) {
        console.log("[ULTIMATE-BYPASS] NSURLSession hook error: " + e);
    }

    // =========================
    // METHOD 2: NSError Prevention
    // =========================
    try {
        var NSError = ObjC.classes.NSError;

        // Prevent error creation for dash-related errors
        Interceptor.attach(NSError['+ errorWithDomain:code:userInfo:'].implementation, {
            onEnter: function(args) {
                var domain = new ObjC.Object(args[2]).toString();
                var code = args[3].toInt32();

                // Check for DoorDash or network errors
                if (domain.includes('DoorDash') || domain.includes('ErrorNetworking') ||
                    domain.includes('NSURLError') || code == 403 || code == 401) {

                    console.log("[ULTIMATE-BYPASS] Blocking error creation: " + domain + " code: " + code);

                    // Change to a harmless error
                    args[3] = ptr(0); // Set error code to 0 (no error)
                }
            }
        });

        console.log("[ULTIMATE-BYPASS] NSError prevention installed");

    } catch(e) {
        console.log("[ULTIMATE-BYPASS] NSError hook error: " + e);
    }

    // =========================
    // METHOD 3: HTTP Status Code Override
    // =========================
    try {
        var NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;

        // Override statusCode getter
        Interceptor.attach(NSHTTPURLResponse['- statusCode'].implementation, {
            onLeave: function(retval) {
                var status = retval.toInt32();

                // Get the URL to check if it's dash-related
                try {
                    var url = this.self.URL().absoluteString().toString();

                    if ((status >= 400) && (url.includes('/dashes') || url.includes('schedule'))) {
                        console.log("[ULTIMATE-BYPASS] Changing status " + status + " to 200 for " + url);
                        retval.replace(ptr(200));
                    }
                } catch(e) {}
            }
        });

        console.log("[ULTIMATE-BYPASS] Status code override installed");

    } catch(e) {
        console.log("[ULTIMATE-BYPASS] Status code hook error: " + e);
    }

    // =========================
    // METHOD 4: Alert/Error Dialog Suppression
    // =========================
    try {
        var UIAlertController = ObjC.classes.UIAlertController;

        var originalShow = UIAlertController['+ alertControllerWithTitle:message:preferredStyle:'];
        if (originalShow) {
            Interceptor.attach(originalShow.implementation, {
                onEnter: function(args) {
                    var title = new ObjC.Object(args[2]);
                    var message = new ObjC.Object(args[3]);

                    if (title || message) {
                        var titleStr = title ? title.toString() : "";
                        var msgStr = message ? message.toString() : "";

                        // Block error alerts
                        if (titleStr.includes('Error') || msgStr.includes('error') ||
                            msgStr.includes('403') || msgStr.includes('log out') ||
                            msgStr.includes('unable to start')) {

                            console.log("[ULTIMATE-BYPASS] Blocking error alert: " + msgStr);

                            // Return null to prevent alert
                            args[2] = null;
                            args[3] = null;
                        }
                    }
                }
            });
        }

        console.log("[ULTIMATE-BYPASS] Alert suppression installed");

    } catch(e) {
        console.log("[ULTIMATE-BYPASS] Alert hook error: " + e);
    }

    // =========================
    // Basic iOS Spoofing
    // =========================
    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function(retval) {
                retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
            }
        });
        console.log("[ULTIMATE-BYPASS] iOS spoofed to 17.6.1");
    } catch(e) {}

    // =========================
    // Summary
    // =========================
    console.log("\n" + "=".repeat(60));
    console.log("ULTIMATE 403 BYPASS ACTIVE");
    console.log("=".repeat(60));
    console.log("✓ Network response modification");
    console.log("✓ Error prevention");
    console.log("✓ Status code override");
    console.log("✓ Alert suppression");
    console.log("✓ iOS version spoofing");
    console.log("=".repeat(60));
    console.log("Try tapping 'Schedule/Dash Now' - errors should be bypassed");
    console.log("=".repeat(60) + "\n");

} else {
    console.log("[ULTIMATE-BYPASS] ObjC not available!");
}