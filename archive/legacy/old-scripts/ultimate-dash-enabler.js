// Ultimate Dash Enabler - Forces Dash Now Button and Overrides ALL Restrictions
console.log("[DASH-ENABLER] Starting ultimate dash enabler...");

if (ObjC.available) {

    // ========================================
    // 1. MONITOR AND OVERRIDE ALL DASH ENDPOINTS
    // ========================================
    var NSURLSession = ObjC.classes.NSURLSession;

    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter: function(args) {
            var request = new ObjC.Object(args[2]);
            var url = request.URL().absoluteString().toString();

            // Track ALL endpoints for debugging
            console.log("[DASH-ENABLER] API Request: " + url);

            if (args[3]) {
                var handler = new ObjC.Block(args[3]);
                var origImpl = handler.implementation;

                handler.implementation = function(data, response, error) {
                    if (data) {
                        try {
                            var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                            if (str) {
                                var content = str.toString();

                                // Log ALL responses for dash-related endpoints
                                if (url.includes('dash') || url.includes('shift') ||
                                    url.includes('schedule') || url.includes('eligib') ||
                                    url.includes('market') || url.includes('zone')) {

                                    console.log("[DASH-ENABLER] Response from " + url);
                                    console.log("[DASH-ENABLER] Content (first 800 chars): " + content.substring(0, 800));

                                    // Parse JSON to check restrictions
                                    try {
                                        var jsonObj = JSON.parse(content);

                                        // Check for any restriction fields
                                        if (jsonObj.can_dash !== undefined) console.log("[DASH-ENABLER] can_dash = " + jsonObj.can_dash);
                                        if (jsonObj.eligible_to_dash !== undefined) console.log("[DASH-ENABLER] eligible_to_dash = " + jsonObj.eligible_to_dash);
                                        if (jsonObj.dash_now_available !== undefined) console.log("[DASH-ENABLER] dash_now_available = " + jsonObj.dash_now_available);
                                        if (jsonObj.is_restricted !== undefined) console.log("[DASH-ENABLER] is_restricted = " + jsonObj.is_restricted);
                                        if (jsonObj.account_status !== undefined) console.log("[DASH-ENABLER] account_status = " + jsonObj.account_status);
                                        if (jsonObj.market_open !== undefined) console.log("[DASH-ENABLER] market_open = " + jsonObj.market_open);
                                        if (jsonObj.zones_available !== undefined) console.log("[DASH-ENABLER] zones_available = " + jsonObj.zones_available);

                                    } catch(e) {}

                                    // AGGRESSIVE OVERRIDE - Enable everything
                                    var modified = content
                                        // Boolean flags
                                        .replace(/"can_dash":\s*false/g, '"can_dash":true')
                                        .replace(/"eligible_to_dash":\s*false/g, '"eligible_to_dash":true')
                                        .replace(/"dash_now_available":\s*false/g, '"dash_now_available":true')
                                        .replace(/"is_restricted":\s*true/g, '"is_restricted":false')
                                        .replace(/"is_eligible":\s*false/g, '"is_eligible":true')
                                        .replace(/"can_schedule":\s*false/g, '"can_schedule":true')
                                        .replace(/"market_open":\s*false/g, '"market_open":true')
                                        .replace(/"is_active":\s*false/g, '"is_active":true')
                                        .replace(/"is_approved":\s*false/g, '"is_approved":true')
                                        .replace(/"has_zones":\s*false/g, '"has_zones":true')

                                        // Status strings
                                        .replace(/"account_status":\s*"deactivated"/g, '"account_status":"active"')
                                        .replace(/"account_status":\s*"restricted"/g, '"account_status":"active"')
                                        .replace(/"account_status":\s*"suspended"/g, '"account_status":"active"')
                                        .replace(/"dasher_status":\s*"inactive"/g, '"dasher_status":"active"')
                                        .replace(/"dasher_status":\s*"restricted"/g, '"dasher_status":"active"')

                                        // Market/zone restrictions
                                        .replace(/"zones_available":\s*\[\]/g, '"zones_available":[{"id":1,"name":"Zone 1","active":true}]')
                                        .replace(/"available_shifts":\s*\[\]/g, '"available_shifts":[{"start":"now","end":"later","available":true}]')

                                        // Error messages
                                        .replace(/"error":\s*"[^"]*"/g, '"error":null')
                                        .replace(/"errors":\s*\[[^\]]*\]/g, '"errors":[]');

                                    if (modified !== content) {
                                        console.log("[DASH-ENABLER] ✅ MODIFIED RESPONSE - Enabled dashing!");
                                        var newData = ObjC.classes.NSString.stringWithString_(modified).dataUsingEncoding_(4);
                                        return origImpl(newData, response, error);
                                    }
                                }
                            }
                        } catch(e) {
                            console.log("[DASH-ENABLER] Error processing response: " + e);
                        }
                    }

                    return origImpl(data, response, error);
                };
            }
        }
    });

    // ========================================
    // 2. FORCE CREATE DASH NOW BUTTON
    // ========================================
    setTimeout(function() {
        dispatch_async(dispatch_get_main_queue(), function() {
            try {
                var app = ObjC.classes.UIApplication.sharedApplication();
                var keyWindow = app.keyWindow();

                // Function to inject button
                function injectDashButton(parentView) {
                    console.log("[DASH-ENABLER] Attempting to inject Dash Now button...");

                    // Create a new button
                    var UIButton = ObjC.classes.UIButton;
                    var dashButton = UIButton.buttonWithType_(0); // Custom type

                    // Set button properties
                    dashButton.setTitle_forState_("Dash Now", 0);
                    dashButton.setBackgroundColor_(ObjC.classes.UIColor.systemRedColor());
                    dashButton.setTitleColor_forState_(ObjC.classes.UIColor.whiteColor(), 0);

                    // Set frame
                    var frame = dashButton.frame();
                    frame.origin.x = 20;
                    frame.origin.y = 100;
                    frame.size.width = parentView.bounds().size.width - 40;
                    frame.size.height = 50;
                    dashButton.setFrame_(frame);

                    // Make it rounded
                    dashButton.layer().setCornerRadius_(8);
                    dashButton.clipsToBounds = true;

                    // Add to view
                    parentView.addSubview_(dashButton);
                    parentView.bringSubviewToFront_(dashButton);

                    console.log("[DASH-ENABLER] ✅ Injected Dash Now button!");

                    // Add tap handler (trigger dash functionality)
                    dashButton.addTarget_action_forControlEvents_(app.delegate(),
                        ObjC.selector("handleDashNowTapped:"), 64); // TouchUpInside
                }

                // Find the main view controller
                function findMainViewController(view, depth) {
                    if (depth > 15) return null;

                    // Look for tab bar or main content view
                    if (view.isKindOfClass_(ObjC.classes.UITabBar) ||
                        view.isKindOfClass_(ObjC.classes.UINavigationBar)) {
                        console.log("[DASH-ENABLER] Found main UI element");

                        // Get parent view
                        var superview = view.superview();
                        if (superview) {
                            injectDashButton(superview);
                            return superview;
                        }
                    }

                    var subviews = view.subviews();
                    if (subviews) {
                        for (var i = 0; i < subviews.count(); i++) {
                            var result = findMainViewController(subviews.objectAtIndex_(i), depth + 1);
                            if (result) return result;
                        }
                    }

                    return null;
                }

                if (keyWindow) {
                    console.log("[DASH-ENABLER] Searching for injection point...");
                    findMainViewController(keyWindow, 0);
                }

            } catch(e) {
                console.log("[DASH-ENABLER] UI injection error: " + e);
            }
        });
    }, 3000); // Wait 3 seconds for app to load

    // ========================================
    // 3. OVERRIDE VIEW CONTROLLER METHODS
    // ========================================

    // Hook viewDidLoad to ensure dash options are shown
    try {
        // Find DoorDash view controllers
        var classes = ObjC.enumerateLoadedClassesSync();
        for (var i = 0; i < classes.length; i++) {
            var className = classes[i];

            // Target DoorDash view controllers
            if (className.includes("Dash") || className.includes("Schedule") ||
                className.includes("Home") || className.includes("Main")) {

                try {
                    var ViewController = ObjC.classes[className];

                    if (ViewController['- viewDidLoad']) {
                        Interceptor.attach(ViewController['- viewDidLoad'].implementation, {
                            onLeave: function() {
                                console.log("[DASH-ENABLER] Hooked " + className + " viewDidLoad");

                                // Force dash availability
                                dispatch_async(dispatch_get_main_queue(), function() {
                                    try {
                                        // Try to enable any dash-related UI elements
                                        var viewController = this.context;

                                        // Look for any disabled buttons and enable them
                                        var view = viewController.view();
                                        enableAllButtons(view, 0);

                                    } catch(e) {}
                                });
                            }
                        });
                    }

                } catch(e) {}
            }
        }
    } catch(e) {
        console.log("[DASH-ENABLER] ViewController hook error: " + e);
    }

    // Helper function to enable all buttons
    function enableAllButtons(view, depth) {
        if (depth > 10 || !view) return;

        if (view.isKindOfClass_(ObjC.classes.UIButton)) {
            view.setEnabled_(true);
            view.setUserInteractionEnabled_(true);
            view.setAlpha_(1.0);

            var title = view.titleLabel();
            if (title && title.text()) {
                var text = title.text().toString().toLowerCase();
                if (text.includes("dash") || text.includes("schedule")) {
                    console.log("[DASH-ENABLER] ✅ Enabled button: " + text);
                    view.setHidden_(false);
                }
            }
        }

        var subviews = view.subviews();
        if (subviews) {
            for (var i = 0; i < subviews.count(); i++) {
                enableAllButtons(subviews.objectAtIndex_(i), depth + 1);
            }
        }
    }

    // ========================================
    // 4. SPOOF LOCATION TO BUSY MARKET
    // ========================================
    try {
        var CLLocationManager = ObjC.classes.CLLocationManager;

        Interceptor.attach(CLLocationManager['- location'].implementation, {
            onLeave: function(retval) {
                // San Francisco coordinates (always busy market)
                var CLLocation = ObjC.classes.CLLocation;
                var spoofedLocation = CLLocation.alloc().initWithLatitude_longitude_(37.7749, -122.4194);

                console.log("[DASH-ENABLER] Spoofed location to San Francisco");
                retval.replace(spoofedLocation);
            }
        });
    } catch(e) {}

    // ========================================
    // 5. OVERRIDE USER DEFAULTS
    // ========================================
    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;

        Interceptor.attach(NSUserDefaults['- boolForKey:'].implementation, {
            onEnter: function(args) {
                var key = ObjC.Object(args[2]).toString();
                this.key = key;
            },
            onLeave: function(retval) {
                // Override dash-related settings
                if (this.key.toLowerCase().includes('dash') ||
                    this.key.toLowerCase().includes('eligible') ||
                    this.key.toLowerCase().includes('restrict')) {

                    console.log("[DASH-ENABLER] Overriding setting: " + this.key + " = true");
                    retval.replace(ptr(1)); // Return YES
                }
            }
        });
    } catch(e) {}

    console.log("\n" + "=".repeat(60));
    console.log("🚀 ULTIMATE DASH ENABLER ACTIVE 🚀");
    console.log("=".repeat(60));
    console.log("✅ API response modification active");
    console.log("✅ UI button injection ready");
    console.log("✅ ViewController hooks installed");
    console.log("✅ Location spoofed to busy market");
    console.log("✅ User defaults overridden");
    console.log("=".repeat(60));
    console.log("ACTION REQUIRED:");
    console.log("1. Pull down to refresh the main screen");
    console.log("2. Check for Dash Now button");
    console.log("3. If still missing, navigate to Schedule tab");
    console.log("4. Watch console for API responses");
    console.log("=".repeat(60) + "\n");

} else {
    console.log("[DASH-ENABLER] ObjC not available!");
}