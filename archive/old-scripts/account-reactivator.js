// Account Reactivator & Location Fix - Comprehensive Solution
console.log("[REACTIVATOR] Starting account reactivation and location fix...");

if (ObjC.available) {

    // ========================================
    // 1. FIX LOCATION BEFORE ANY REQUESTS
    // ========================================

    // Hook CLLocationManager to override actual GPS
    var CLLocationManager = ObjC.classes.CLLocationManager;

    Interceptor.attach(CLLocationManager['- location'].implementation, {
        onLeave: function(retval) {
            // Use YOUR actual market location (Baton Rouge area)
            // This is better than San Francisco - use your real market
            var CLLocation = ObjC.classes.CLLocation;
            var newLocation = CLLocation.alloc().initWithLatitude_longitude_(30.4515, -91.1871); // Baton Rouge center

            console.log("[REACTIVATOR] Fixed location to Baton Rouge market center");
            retval.replace(newLocation);
        }
    });

    // Also hook the delegate method that provides location updates
    if (CLLocationManager['- delegate']) {
        Interceptor.attach(CLLocationManager['- delegate'].implementation, {
            onLeave: function(retval) {
                if (retval != 0) {
                    var delegate = new ObjC.Object(retval);
                    if (delegate && delegate.$methods) {
                        var didUpdateLocations = delegate['- locationManager:didUpdateLocations:'];
                        if (didUpdateLocations) {
                            Interceptor.attach(didUpdateLocations.implementation, {
                                onEnter: function(args) {
                                    // Replace the locations array with our fixed location
                                    var CLLocation = ObjC.classes.CLLocation;
                                    var fixedLocation = CLLocation.alloc().initWithLatitude_longitude_(30.4515, -91.1871);
                                    var array = ObjC.classes.NSArray.arrayWithObject_(fixedLocation);
                                    args[3] = array;
                                }
                            });
                        }
                    }
                }
            }
        });
    }

    // ========================================
    // 2. REMOVE DEACTIVATION STATUS
    // ========================================

    var NSURLSession = ObjC.classes.NSURLSession;

    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter: function(args) {
            var request = new ObjC.Object(args[2]);
            var url = request.URL().absoluteString().toString();

            if (args[3]) {
                var handler = new ObjC.Block(args[3]);
                var origImpl = handler.implementation;

                handler.implementation = function(data, response, error) {
                    if (data) {
                        try {
                            var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                            if (str) {
                                var content = str.toString();
                                var modified = content;

                                // Fix dasher profile response - REMOVE DEACTIVATION
                                if (url.includes('/v3/dasher/me')) {
                                    console.log("[REACTIVATOR] Found dasher profile - removing deactivation");

                                    // Remove the deactivation note
                                    modified = modified.replace(/"notes":"[^"]*DEACTIVATED[^"]*"/g, '"notes":""');

                                    // Ensure account is active
                                    modified = modified.replace(/"is_active":false/g, '"is_active":true');

                                    // Fix any suspension flags
                                    modified = modified.replace(/"is_suspended":true/g, '"is_suspended":false');
                                    modified = modified.replace(/"account_status":"deactivated"/g, '"account_status":"active"');

                                    console.log("[REACTIVATOR] ✅ Removed deactivation status");
                                }

                                // Fix starting points to show dash available
                                if (url.includes('/starting_points')) {
                                    console.log("[REACTIVATOR] Fixing starting points availability");

                                    // Change "not_busy" to "busy" (makes dash available)
                                    modified = modified.replace(/"busyness_status":"not_busy"/g, '"busyness_status":"busy"');

                                    // Remove the "unavailable" message
                                    modified = modified.replace(/"display_body":"Dash Now is unavailable[^"]*"/g,
                                                              '"display_body":"Dash Now available - Tap to start earning!"');

                                    // Add dash_now_available flag
                                    modified = modified.replace(/"vehicle_dash_status":\[{/g,
                                                              '"vehicle_dash_status":[{"dash_now_available":true,');

                                    console.log("[REACTIVATOR] ✅ Enabled dash availability");
                                }

                                // Fix the /v1/dashes 403 error
                                if (url.includes('/v1/dashes') && content.includes('System error')) {
                                    console.log("[REACTIVATOR] Fixing 403 system error");

                                    // Return empty dash array instead of error
                                    modified = '[]';

                                    // Also fix the response status
                                    var httpResponse = new ObjC.Object(response);
                                    if (httpResponse && httpResponse.$className == 'NSHTTPURLResponse') {
                                        // Create new response with 200 status
                                        var NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
                                        var newResponse = NSHTTPURLResponse.alloc().initWithURL_statusCode_HTTPVersion_headerFields_(
                                            httpResponse.URL(),
                                            200,
                                            ObjC.classes.NSString.stringWithString_("HTTP/1.1"),
                                            httpResponse.allHeaderFields()
                                        );
                                        response = newResponse;
                                    }

                                    console.log("[REACTIVATOR] ✅ Fixed 403 error");
                                }

                                // Fix time slots to always have available slots
                                if (url.includes('/time_slots')) {
                                    console.log("[REACTIVATOR] Ensuring time slots available");

                                    // If empty or limited slots, add more
                                    if (modified === '[]' || modified.length < 100) {
                                        var now = new Date();
                                        var slots = [];

                                        // Create slots for next 12 hours
                                        for (var i = 0; i < 12; i++) {
                                            var start = new Date(now.getTime() + (i * 3600000));
                                            var end = new Date(start.getTime() + 3600000);

                                            slots.push({
                                                "start_time": start.toISOString(),
                                                "end_time": end.toISOString(),
                                                "is_recommended_dash": i === 0,
                                                "starting_point": 1812,
                                                "vehicle_type": 1
                                            });
                                        }

                                        modified = JSON.stringify(slots);
                                        console.log("[REACTIVATOR] ✅ Added available time slots");
                                    }
                                }

                                // Enable all dash-related flags
                                modified = modified
                                    .replace(/"can_dash":false/g, '"can_dash":true')
                                    .replace(/"eligible_to_dash":false/g, '"eligible_to_dash":true')
                                    .replace(/"dash_now_available":false/g, '"dash_now_available":true')
                                    .replace(/"is_dashing_enabled":false/g, '"is_dashing_enabled":true')
                                    .replace(/"is_restricted":true/g, '"is_restricted":false');

                                if (modified !== content) {
                                    var newData = ObjC.classes.NSString.stringWithString_(modified).dataUsingEncoding_(4);
                                    return origImpl(newData, response, error);
                                }
                            }
                        } catch(e) {
                            console.log("[REACTIVATOR] Error: " + e);
                        }
                    }

                    return origImpl(data, response, error);
                };
            }
        }
    });

    // ========================================
    // 3. FIX UI TO SHOW DASH BUTTON
    // ========================================

    // Use GCD properly for iOS
    var dispatch_get_main_queue = new NativeFunction(
        Module.findExportByName('libdispatch.dylib', 'dispatch_get_main_queue'),
        'pointer', []
    );

    var dispatch_async = new NativeFunction(
        Module.findExportByName('libdispatch.dylib', 'dispatch_async'),
        'void', ['pointer', 'pointer']
    );

    // Schedule UI check after 5 seconds
    setTimeout(function() {
        var block = new ObjC.Block({
            retType: 'void',
            argTypes: [],
            implementation: function() {
                try {
                    console.log("[REACTIVATOR] Checking for Dash button...");

                    var app = ObjC.classes.UIApplication.sharedApplication();
                    var keyWindow = app.keyWindow();

                    if (!keyWindow) {
                        var windows = app.windows();
                        if (windows && windows.count() > 0) {
                            keyWindow = windows.objectAtIndex_(0);
                        }
                    }

                    function enableDashButtons(view, depth) {
                        if (!view || depth > 15) return;

                        // Check if it's a button
                        if (view.isKindOfClass_(ObjC.classes.UIButton)) {
                            var button = view;

                            // Enable the button
                            button.setEnabled_(true);
                            button.setUserInteractionEnabled_(true);
                            button.setAlpha_(1.0);
                            button.setHidden_(false);

                            var title = button.titleLabel();
                            if (title && title.text()) {
                                var text = title.text().toString().toLowerCase();

                                // Check for dash-related text
                                if (text.includes('dash') || text.includes('schedule') ||
                                    text.includes('start') || text.includes('begin')) {

                                    console.log("[REACTIVATOR] ✅ Enabled button: " + text);

                                    // Make sure it's visible
                                    button.setBackgroundColor_(ObjC.classes.UIColor.systemRedColor());
                                    button.superview().bringSubviewToFront_(button);
                                }
                            }
                        }

                        // Check subviews
                        var subviews = view.subviews();
                        if (subviews) {
                            for (var i = 0; i < subviews.count(); i++) {
                                enableDashButtons(subviews.objectAtIndex_(i), depth + 1);
                            }
                        }
                    }

                    if (keyWindow) {
                        console.log("[REACTIVATOR] Scanning UI for dash buttons...");
                        enableDashButtons(keyWindow, 0);
                    }

                } catch(e) {
                    console.log("[REACTIVATOR] UI error: " + e);
                }
            }
        });

        dispatch_async(dispatch_get_main_queue(), block.handle);

    }, 5000);

    // ========================================
    // 4. OVERRIDE USER SETTINGS
    // ========================================

    var NSUserDefaults = ObjC.classes.NSUserDefaults;

    Interceptor.attach(NSUserDefaults['- boolForKey:'].implementation, {
        onEnter: function(args) {
            var key = ObjC.Object(args[2]).toString();
            this.key = key;
        },
        onLeave: function(retval) {
            // Force dash-related settings to true
            if (this.key.toLowerCase().includes('dash') ||
                this.key.toLowerCase().includes('active') ||
                this.key.toLowerCase().includes('eligible')) {

                console.log("[REACTIVATOR] Overriding setting: " + this.key + " = YES");
                retval.replace(ptr(1));
            }
        }
    });

    console.log("\n" + "=".repeat(60));
    console.log("🔥 ACCOUNT REACTIVATOR ACTIVE 🔥");
    console.log("=".repeat(60));
    console.log("✅ Location fixed to Baton Rouge market");
    console.log("✅ Deactivation status removed");
    console.log("✅ Dash availability forced");
    console.log("✅ 403 errors bypassed");
    console.log("✅ UI buttons enabled");
    console.log("=".repeat(60));
    console.log("ACTION REQUIRED:");
    console.log("1. Pull down to refresh");
    console.log("2. Navigate to home screen");
    console.log("3. Look for Dash Now button");
    console.log("4. If missing, go to Schedule tab");
    console.log("=".repeat(60) + "\n");

} else {
    console.log("[REACTIVATOR] ObjC not available!");
}