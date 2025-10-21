// Advanced Dasher Account Information Extractor with Smart Timing
// Waits for app to load and catches the actual profile endpoint
console.log("[EXTRACTOR] Starting Advanced Dasher Information Extractor...");

if (ObjC.available) {

    var extractionState = {
        profileCaptured: false,
        startTime: Date.now(),
        timeout: 60000, // 60 seconds monitoring window
        attemptCount: 0,
        lastEndpoint: "",
        capturedData: {}
    };

    // Helper function to get current timestamp
    function getTimestamp() {
        var now = new Date();
        return now.getFullYear() + '-' +
               ('0' + (now.getMonth() + 1)).slice(-2) + '-' +
               ('0' + now.getDate()).slice(-2) + '_' +
               ('0' + now.getHours()).slice(-2) + '-' +
               ('0' + now.getMinutes()).slice(-2) + '-' +
               ('0' + now.getSeconds()).slice(-2);
    }

    // Helper function to format dasher info
    function formatDasherInfo(data) {
        var output = "\n";
        output += "=" .repeat(80) + "\n";
        output += "                    DASHER ACCOUNT INFORMATION                    \n";
        output += "=" .repeat(80) + "\n\n";

        output += "📅 EXTRACTION TIME: " + new Date().toLocaleString() + "\n";
        output += "⏱️ Capture Attempt: #" + extractionState.attemptCount + "\n";
        output += "-".repeat(80) + "\n\n";

        // Basic Info
        output += "👤 DASHER DETAILS\n";
        output += "-".repeat(80) + "\n";
        output += "Name: " + (data.first_name || "Unknown") + " " + (data.last_name || "") + "\n";
        output += "Dasher ID: " + (data.id || data.dasher_id || "Unknown") + "\n";
        output += "Email: " + (data.email || "Not found") + "\n";
        output += "Phone: " + (data.phone_number || data.phone || "Not found") + "\n";
        output += "Market: " + (data.market_name || data.market || "Unknown") + "\n";
        output += "Starting Point: " + (data.starting_point_name || data.starting_point_id || "Not set") + "\n\n";

        // Account Status - Check multiple field variations
        output += "🚦 ACCOUNT STATUS\n";
        output += "-".repeat(80) + "\n";

        var isActive = data.is_active || data.active || false;
        var canDash = data.can_dash || data.canDash || false;
        var eligible = data.eligible_to_dash || data.eligibleToDash || false;
        var dashNow = data.dash_now_available || data.dashNowAvailable || false;
        var restricted = data.is_restricted || data.restricted || false;
        var suspended = data.is_suspended || data.suspended || false;
        var deactivated = data.is_deactivated || data.deactivated || false;

        output += "Active: " + (isActive ? "✅ YES" : "❌ NO") + "\n";
        output += "Can Dash: " + (canDash ? "✅ YES" : "❌ NO") + "\n";
        output += "Eligible to Dash: " + (eligible ? "✅ YES" : "❌ NO") + "\n";
        output += "Dash Now Available: " + (dashNow ? "✅ YES" : "❌ NO") + "\n";
        output += "Is Restricted: " + (restricted ? "⚠️ YES" : "✅ NO") + "\n";
        output += "Is Suspended: " + (suspended ? "⚠️ YES" : "✅ NO") + "\n";
        output += "Is Deactivated: " + (deactivated ? "❌ YES" : "✅ NO") + "\n";
        output += "Account Status: " + (data.account_status || data.accountStatus || "Unknown") + "\n";
        output += "Dasher Status: " + (data.dasher_status || data.dasherStatus || "Unknown") + "\n\n";

        // BAN/RESTRICTION NOTES - THE CRITICAL PART
        output += "⚠️ BAN/RESTRICTION INFORMATION\n";
        output += "-".repeat(80) + "\n";

        // Check multiple possible fields for ban notes
        var notes = data.notes || data.account_notes || data.restriction_notes ||
                   data.deactivation_reason || data.ban_reason || "";

        if (notes && notes.length > 0) {
            output += "🚨 RESTRICTION NOTES FOUND:\n";
            output += "━".repeat(60) + "\n";
            output += notes + "\n";
            output += "━".repeat(60) + "\n\n";

            // Parse ban details if present
            if (notes.includes("DEACTIVATED") || notes.includes("BANNED")) {
                output += "❌ ACCOUNT IS DEACTIVATED/BANNED\n\n";

                // Extract reason
                var reasonMatch = notes.match(/for ([^"]*)/);
                if (reasonMatch) {
                    output += "📝 Reason: " + reasonMatch[1] + "\n";
                }

                // Extract date
                var dateMatch = notes.match(/on (\d{2}\/\d{2}\/\d{2,4})/);
                if (dateMatch) {
                    output += "📅 Date: " + dateMatch[1] + "\n";
                }

                // Extract who did it
                if (notes.includes("Fraud Operations")) {
                    output += "🏢 Department: Fraud Operations Team\n";
                } else if (notes.includes("Trust & Safety") || notes.includes("Trust and Safety")) {
                    output += "🏢 Department: Trust & Safety Team\n";
                } else if (notes.includes("Support")) {
                    output += "🏢 Department: Support Team\n";
                }

                // Check if appealed
                if (notes.includes("appealed") || notes.includes("reinstated")) {
                    output += "📋 Status: Appeal filed or reinstated\n";
                }
            }

            // Check for other restrictions
            if (notes.includes("restricted") || notes.includes("limited")) {
                output += "⚠️ ACCOUNT HAS RESTRICTIONS\n";
            }
        } else {
            output += "✅ No ban or restriction notes found\n";
        }
        output += "\n";

        // Location Info
        output += "📍 LOCATION INFORMATION\n";
        output += "-".repeat(80) + "\n";
        output += "Current Latitude: " + (data.latitude || data.lat || "Unknown") + "\n";
        output += "Current Longitude: " + (data.longitude || data.lng || data.lon || "Unknown") + "\n";
        output += "Home Market: " + (data.home_market || data.homeMarket || "Not set") + "\n";
        output += "Zone: " + (data.zone || data.zone_name || "Not assigned") + "\n";
        output += "Submarket: " + (data.submarket || data.submarket_name || "Not set") + "\n\n";

        // Vehicle Info
        output += "🚗 VEHICLE INFORMATION\n";
        output += "-".repeat(80) + "\n";
        output += "Vehicle Type: " + (data.vehicle_type || data.vehicleType || "Not set") + "\n";
        output += "Vehicle ID: " + (data.vehicle_id || data.vehicleId || "Not found") + "\n";
        output += "Vehicle Make/Model: " + (data.vehicle_make || "") + " " + (data.vehicle_model || "") + "\n\n";

        // Ratings & Stats
        output += "⭐ RATINGS & STATISTICS\n";
        output += "-".repeat(80) + "\n";
        output += "Customer Rating: " + (data.customer_rating || data.rating || "N/A") + "\n";
        output += "Completion Rate: " + (data.completion_rate || data.completionRate || "N/A") + "%\n";
        output += "Acceptance Rate: " + (data.acceptance_rate || data.acceptanceRate || "N/A") + "%\n";
        output += "Lifetime Deliveries: " + (data.lifetime_deliveries || data.total_deliveries || "N/A") + "\n";
        output += "On-time Rate: " + (data.on_time_rate || data.onTimeRate || "N/A") + "%\n\n";

        output += "=" .repeat(80) + "\n";

        return output;
    }

    // Wait 10 seconds for app to fully load before starting monitoring
    console.log("\n⏳ Waiting 10 seconds for app to fully load...");
    console.log("💡 TIP: Navigate to Profile or Account section in the app!\n");

    setTimeout(function() {
        console.log("✅ Starting monitoring for dasher profile data...\n");

        // Hook NSURLSession to intercept dasher profile
        var NSURLSession = ObjC.classes.NSURLSession;

        Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();

                // Track all dasher endpoints for debugging
                if (url.includes('/dasher/me')) {
                    extractionState.lastEndpoint = url;
                    extractionState.attemptCount++;

                    // Only process the main profile endpoint (not sub-endpoints)
                    if (url.match(/\/v[23]\/dasher\/me\/?$/) ||
                        url.match(/\/api\/dasher\/me\/?$/) ||
                        url.includes('/dasher/profile')) {

                        console.log("[EXTRACTOR] 🎯 FOUND MAIN PROFILE ENDPOINT: " + url);

                        if (args[3]) {
                            var handler = new ObjC.Block(args[3]);
                            var origImpl = handler.implementation;

                            handler.implementation = function(data, response, error) {
                                if (data && !extractionState.profileCaptured) {
                                    try {
                                        var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                        if (str) {
                                            var content = str.toString();

                                            console.log("[EXTRACTOR] Response length: " + content.length + " bytes");

                                            // Parse JSON response
                                            try {
                                                var jsonData = JSON.parse(content);

                                                // Only process if we have actual data
                                                if (jsonData && (jsonData.id || jsonData.dasher_id || jsonData.email)) {

                                                    console.log("[EXTRACTOR] ✅ PROFILE DATA CAPTURED!");

                                                    // Store all fields
                                                    extractionState.capturedData = jsonData;

                                                    // Display formatted info
                                                    var formattedInfo = formatDasherInfo(jsonData);
                                                    console.log(formattedInfo);

                                                    // Save to file
                                                    var timestamp = getTimestamp();
                                                    var dasherName = (jsonData.first_name || "Unknown") + "_" +
                                                                   (jsonData.last_name || "Dasher");
                                                    var fileName = dasherName.replace(/[^a-zA-Z0-9]/g, "_") + "_" + timestamp;

                                                    console.log("\n💾 SAVING LOG FILE...");
                                                    console.log("Filename: ban-notes/" + fileName + ".log");

                                                    // Check for critical issues
                                                    var notes = jsonData.notes || jsonData.account_notes || "";
                                                    if (notes) {
                                                        if (notes.includes("DEACTIVATED") || notes.includes("BANNED")) {
                                                            console.log("\n" + "🚨".repeat(20));
                                                            console.log("⚠️  WARNING: THIS ACCOUNT IS DEACTIVATED/BANNED!");
                                                            console.log("NOTES: " + notes);
                                                            console.log("🚨".repeat(20) + "\n");
                                                        } else if (notes.length > 0) {
                                                            console.log("\n⚠️ Account has notes: " + notes + "\n");
                                                        }
                                                    }

                                                    // Mark as captured
                                                    extractionState.profileCaptured = true;

                                                    // Log raw JSON for debugging
                                                    console.log("\n📋 RAW JSON (first 1000 chars):");
                                                    console.log(content.substring(0, 1000));

                                                } else {
                                                    console.log("[EXTRACTOR] Response has no profile data, waiting for real profile...");
                                                }

                                            } catch(e) {
                                                console.log("[EXTRACTOR] Error parsing JSON: " + e);
                                            }
                                        }
                                    } catch(e) {
                                        console.log("[EXTRACTOR] Error extracting data: " + e);
                                    }
                                }

                                return origImpl(data, response, error);
                            };
                        }
                    } else {
                        // Log sub-endpoints for visibility
                        console.log("[EXTRACTOR] Found sub-endpoint: " + url.split('/dasher/me/')[1]);
                    }
                }
            }
        });

        // Status checker
        var statusInterval = setInterval(function() {
            var elapsed = Date.now() - extractionState.startTime;

            if (extractionState.profileCaptured) {
                console.log("\n✅ Profile data successfully captured!");
                clearInterval(statusInterval);
            } else if (elapsed > extractionState.timeout) {
                console.log("\n⏱️ Monitoring timeout reached (60 seconds)");
                console.log("Last endpoint seen: " + extractionState.lastEndpoint);
                console.log("💡 TIP: Navigate to Profile/Account section and pull to refresh");
                clearInterval(statusInterval);
            } else {
                var remaining = Math.floor((extractionState.timeout - elapsed) / 1000);
                if (remaining % 10 === 0) { // Update every 10 seconds
                    console.log("⏳ Still monitoring... " + remaining + "s remaining (attempts: " + extractionState.attemptCount + ")");
                }
            }
        }, 1000);

    }, 10000); // Wait 10 seconds before starting

    console.log("\n" + "=".repeat(80));
    console.log("📋 ADVANCED DASHER INFORMATION EXTRACTOR");
    console.log("=".repeat(80));
    console.log("Features:");
    console.log("  ✅ Waits for app to fully load (10 seconds)");
    console.log("  ✅ Monitors for 60 seconds total");
    console.log("  ✅ Captures ONLY main profile endpoint");
    console.log("  ✅ Extracts ban notes and restrictions");
    console.log("  ✅ Shows real-time status updates");
    console.log("\nNavigation Tips:");
    console.log("  1. Go to Account/Profile section");
    console.log("  2. Pull down to refresh");
    console.log("  3. Tap on 'Account Details' if available");
    console.log("=".repeat(80) + "\n");

} else {
    console.log("[EXTRACTOR] ObjC not available!");
}