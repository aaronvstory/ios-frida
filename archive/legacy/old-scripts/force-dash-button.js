// Force Dash Now Button to Appear
console.log("[DASH-FIX] Starting dash button force script...");

if (ObjC.available) {

    // Monitor all API responses to see what's happening
    try {
        var NSURLSession = ObjC.classes.NSURLSession;

        Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();

                // Log all dash-related endpoints
                if (url.includes('dash') || url.includes('schedule') || url.includes('shift')) {
                    console.log("[DASH-FIX] Request to: " + url);

                    if (args[3]) {
                        var handler = new ObjC.Block(args[3]);
                        var origImpl = handler.implementation;

                        handler.implementation = function(data, response, error) {
                            if (data) {
                                try {
                                    var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                    if (str) {
                                        var content = str.toString();
                                        console.log("[DASH-FIX] Response: " + content.substring(0, 500));

                                        // Check for dash availability
                                        if (content.includes('"can_dash":false') ||
                                            content.includes('"eligible_to_dash":false') ||
                                            content.includes('"dash_now_available":false')) {

                                            console.log("[DASH-FIX] FOUND RESTRICTION - Attempting to override...");

                                            // Modify response to enable dashing
                                            var modified = content
                                                .replace('"can_dash":false', '"can_dash":true')
                                                .replace('"eligible_to_dash":false', '"eligible_to_dash":true')
                                                .replace('"dash_now_available":false', '"dash_now_available":true')
                                                .replace('"is_restricted":true', '"is_restricted":false')
                                                .replace('"account_status":"deactivated"', '"account_status":"active"')
                                                .replace('"account_status":"restricted"', '"account_status":"active"');

                                            var newData = ObjC.classes.NSString.stringWithString_(modified).dataUsingEncoding_(4);

                                            console.log("[DASH-FIX] Modified response to enable dashing");
                                            return origImpl(newData, response, error);
                                        }
                                    }
                                } catch(e) {}
                            }

                            return origImpl(data, response, error);
                        };
                    }
                }
            }
        });

        console.log("[DASH-FIX] API monitoring installed");

    } catch(e) {
        console.log("[DASH-FIX] Hook error: " + e);
    }

    // Force location to a busy area (optional - uncomment if needed)
    /*
    try {
        var CLLocation = ObjC.classes.CLLocation;

        Interceptor.attach(CLLocation['- coordinate'].implementation, {
            onLeave: function(retval) {
                // San Francisco coordinates (busy market)
                // Latitude: 37.7749, Longitude: -122.4194
                console.log("[DASH-FIX] Spoofing location to San Francisco");
                // This would need proper coordinate structure modification
            }
        });
    } catch(e) {}
    */

    // Check for UI elements related to dashing
    dispatch_async(dispatch_get_main_queue(), function() {
        try {
            // Try to find and log all buttons
            var app = ObjC.classes.UIApplication.sharedApplication();
            var keyWindow = app.keyWindow();

            function findButtons(view, depth) {
                if (depth > 10) return;

                if (view.isKindOfClass_(ObjC.classes.UIButton)) {
                    var button = view;
                    var title = button.titleLabel();
                    if (title) {
                        var text = title.text();
                        if (text) {
                            console.log("[DASH-FIX] Found button: " + text.toString());

                            // Check if it's a scheduling button
                            if (text.toString().toLowerCase().includes('schedule') ||
                                text.toString().toLowerCase().includes('dash')) {
                                console.log("[DASH-FIX] ^^^ This might be your dash button!");
                            }
                        }
                    }
                }

                var subviews = view.subviews();
                if (subviews) {
                    for (var i = 0; i < subviews.count(); i++) {
                        findButtons(subviews.objectAtIndex_(i), depth + 1);
                    }
                }
            }

            if (keyWindow) {
                console.log("[DASH-FIX] Scanning UI for buttons...");
                findButtons(keyWindow, 0);
            }

        } catch(e) {
            console.log("[DASH-FIX] UI scan error: " + e);
        }
    });

    // Basic iOS spoofing
    var UIDevice = ObjC.classes.UIDevice;
    Interceptor.attach(UIDevice['- systemVersion'].implementation, {
        onLeave: function(retval) {
            retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
        }
    });

    console.log("\n" + "=".repeat(60));
    console.log("DASH BUTTON FIX ACTIVE");
    console.log("=".repeat(60));
    console.log("Monitoring API responses for dash restrictions...");
    console.log("Check console output to see what's blocking dash");
    console.log("Try pulling down to refresh the main screen");
    console.log("=".repeat(60) + "\n");

} else {
    console.log("[DASH-FIX] ObjC not available!");
}