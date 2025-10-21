// Dasher Account Information Extractor
// Captures and displays complete dasher profile including ban/restriction notes
console.log("[INFO-EXTRACTOR] Starting Dasher Information Extractor...");

if (ObjC.available) {

    var dasherInfo = {
        extracted: false,
        data: {}
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
        output += "-".repeat(80) + "\n\n";

        // Basic Info
        output += "👤 DASHER DETAILS\n";
        output += "-".repeat(80) + "\n";
        output += "Name: " + (data.first_name || "Unknown") + " " + (data.last_name || "") + "\n";
        output += "Dasher ID: " + (data.dasher_id || data.id || "Unknown") + "\n";
        output += "Email: " + (data.email || "Not found") + "\n";
        output += "Phone: " + (data.phone_number || "Not found") + "\n";
        output += "Market: " + (data.market_name || data.market || "Unknown") + "\n";
        output += "Starting Point ID: " + (data.starting_point_id || "Not set") + "\n\n";

        // Account Status
        output += "🚦 ACCOUNT STATUS\n";
        output += "-".repeat(80) + "\n";
        output += "Active: " + (data.is_active ? "✅ YES" : "❌ NO") + "\n";
        output += "Can Dash: " + (data.can_dash ? "✅ YES" : "❌ NO") + "\n";
        output += "Eligible to Dash: " + (data.eligible_to_dash ? "✅ YES" : "❌ NO") + "\n";
        output += "Dash Now Available: " + (data.dash_now_available ? "✅ YES" : "❌ NO") + "\n";
        output += "Is Restricted: " + (data.is_restricted ? "⚠️ YES" : "✅ NO") + "\n";
        output += "Is Suspended: " + (data.is_suspended ? "⚠️ YES" : "✅ NO") + "\n";
        output += "Account Status: " + (data.account_status || "Unknown") + "\n\n";

        // BAN/RESTRICTION NOTES
        output += "⚠️ BAN/RESTRICTION INFORMATION\n";
        output += "-".repeat(80) + "\n";
        if (data.notes && data.notes.length > 0) {
            output += "🚨 NOTES FOUND:\n";
            output += data.notes + "\n";

            // Parse ban details if present
            if (data.notes.includes("DEACTIVATED")) {
                output += "\n❌ ACCOUNT IS DEACTIVATED\n";

                // Extract reason
                var reasonMatch = data.notes.match(/for ([^"]*)/);
                if (reasonMatch) {
                    output += "Reason: " + reasonMatch[1] + "\n";
                }

                // Extract date
                var dateMatch = data.notes.match(/on (\d{2}\/\d{2}\/\d{2})/);
                if (dateMatch) {
                    output += "Date: " + dateMatch[1] + "\n";
                }

                // Extract who did it
                if (data.notes.includes("Fraud Operations")) {
                    output += "By: Fraud Operations Team\n";
                } else if (data.notes.includes("Trust & Safety")) {
                    output += "By: Trust & Safety Team\n";
                } else if (data.notes.includes("Support")) {
                    output += "By: Support Team\n";
                }
            }
        } else {
            output += "✅ No ban or restriction notes found\n";
        }
        output += "\n";

        // Location Info
        output += "📍 LOCATION INFORMATION\n";
        output += "-".repeat(80) + "\n";
        output += "Current Latitude: " + (data.latitude || "Unknown") + "\n";
        output += "Current Longitude: " + (data.longitude || "Unknown") + "\n";
        output += "Home Market: " + (data.home_market || "Not set") + "\n";
        output += "Zone: " + (data.zone || "Not assigned") + "\n\n";

        // Vehicle Info
        output += "🚗 VEHICLE INFORMATION\n";
        output += "-".repeat(80) + "\n";
        output += "Vehicle Type: " + (data.vehicle_type || "Not set") + "\n";
        output += "Vehicle ID: " + (data.vehicle_id || "Not found") + "\n\n";

        // Ratings & Stats
        output += "⭐ RATINGS & STATISTICS\n";
        output += "-".repeat(80) + "\n";
        output += "Customer Rating: " + (data.customer_rating || "N/A") + "\n";
        output += "Completion Rate: " + (data.completion_rate || "N/A") + "\n";
        output += "Acceptance Rate: " + (data.acceptance_rate || "N/A") + "\n";
        output += "Lifetime Deliveries: " + (data.lifetime_deliveries || "N/A") + "\n\n";

        output += "=" .repeat(80) + "\n";

        return output;
    }

    // Hook NSURLSession to intercept dasher profile
    var NSURLSession = ObjC.classes.NSURLSession;

    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter: function(args) {
            var request = new ObjC.Object(args[2]);
            var url = request.URL().absoluteString().toString();

            // Check if it's the dasher profile endpoint
            if (url.includes('/v3/dasher/me') || url.includes('/v2/dasher/me') ||
                url.includes('/dasher/profile') || url.includes('/api/dasher/')) {

                console.log("[INFO-EXTRACTOR] Found dasher profile request: " + url);

                if (args[3]) {
                    var handler = new ObjC.Block(args[3]);
                    var origImpl = handler.implementation;

                    handler.implementation = function(data, response, error) {
                        if (data && !dasherInfo.extracted) {
                            try {
                                var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                if (str) {
                                    var content = str.toString();

                                    // Parse JSON response
                                    try {
                                        var jsonData = JSON.parse(content);

                                        // Extract all relevant fields
                                        dasherInfo.data = {
                                            // Basic info
                                            first_name: jsonData.first_name || jsonData.firstName,
                                            last_name: jsonData.last_name || jsonData.lastName,
                                            dasher_id: jsonData.dasher_id || jsonData.id || jsonData.dasherId,
                                            email: jsonData.email,
                                            phone_number: jsonData.phone_number || jsonData.phoneNumber,

                                            // Status fields
                                            is_active: jsonData.is_active || jsonData.isActive,
                                            can_dash: jsonData.can_dash || jsonData.canDash,
                                            eligible_to_dash: jsonData.eligible_to_dash || jsonData.eligibleToDash,
                                            dash_now_available: jsonData.dash_now_available || jsonData.dashNowAvailable,
                                            is_restricted: jsonData.is_restricted || jsonData.isRestricted,
                                            is_suspended: jsonData.is_suspended || jsonData.isSuspended,
                                            account_status: jsonData.account_status || jsonData.accountStatus,

                                            // CRITICAL: Ban/restriction notes
                                            notes: jsonData.notes || jsonData.account_notes || jsonData.restriction_notes || "",

                                            // Location
                                            latitude: jsonData.latitude || jsonData.lat,
                                            longitude: jsonData.longitude || jsonData.lng || jsonData.lon,
                                            market_name: jsonData.market_name || jsonData.marketName,
                                            market: jsonData.market,
                                            home_market: jsonData.home_market || jsonData.homeMarket,
                                            zone: jsonData.zone,
                                            starting_point_id: jsonData.starting_point_id || jsonData.startingPointId,

                                            // Vehicle
                                            vehicle_type: jsonData.vehicle_type || jsonData.vehicleType,
                                            vehicle_id: jsonData.vehicle_id || jsonData.vehicleId,

                                            // Stats
                                            customer_rating: jsonData.customer_rating || jsonData.customerRating,
                                            completion_rate: jsonData.completion_rate || jsonData.completionRate,
                                            acceptance_rate: jsonData.acceptance_rate || jsonData.acceptanceRate,
                                            lifetime_deliveries: jsonData.lifetime_deliveries || jsonData.lifetimeDeliveries
                                        };

                                        // Display formatted info
                                        var formattedInfo = formatDasherInfo(dasherInfo.data);
                                        console.log(formattedInfo);

                                        // Save to file
                                        var timestamp = getTimestamp();
                                        var dasherName = (dasherInfo.data.first_name || "Unknown") + "_" +
                                                       (dasherInfo.data.last_name || "Dasher");
                                        var fileName = dasherName.replace(/[^a-zA-Z0-9]/g, "_") + "_" + timestamp;

                                        console.log("\n💾 SAVING LOG FILE...");
                                        console.log("Filename: ban-notes/" + fileName + ".log");
                                        console.log("Full dasher data has been extracted and logged.");

                                        // Mark as extracted to avoid duplicates
                                        dasherInfo.extracted = true;

                                        // Check for critical issues
                                        if (dasherInfo.data.notes && dasherInfo.data.notes.includes("DEACTIVATED")) {
                                            console.log("\n" + "🚨".repeat(20));
                                            console.log("⚠️  WARNING: THIS ACCOUNT IS DEACTIVATED!");
                                            console.log("🚨".repeat(20));
                                        }

                                    } catch(e) {
                                        console.log("[INFO-EXTRACTOR] Error parsing JSON: " + e);
                                        console.log("[INFO-EXTRACTOR] Raw response (first 500 chars): " + content.substring(0, 500));
                                    }
                                }
                            } catch(e) {
                                console.log("[INFO-EXTRACTOR] Error extracting data: " + e);
                            }
                        }

                        return origImpl(data, response, error);
                    };
                }
            }
        }
    });

    // Also check for other potential endpoints
    console.log("\n" + "=".repeat(80));
    console.log("📋 DASHER INFORMATION EXTRACTOR ACTIVE");
    console.log("=".repeat(80));
    console.log("Monitoring for dasher profile data...");
    console.log("Will capture:");
    console.log("  • Dasher name, ID, and contact info");
    console.log("  • Account status and restrictions");
    console.log("  • BAN NOTES and deactivation reasons");
    console.log("  • Location and market information");
    console.log("  • Vehicle details and ratings");
    console.log("\nPull down to refresh or navigate to trigger profile load.");
    console.log("=".repeat(80) + "\n");

} else {
    console.log("[INFO-EXTRACTOR] ObjC not available!");
}