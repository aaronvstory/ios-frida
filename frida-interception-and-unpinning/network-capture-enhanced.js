// Enhanced Network Capture with Real-time Analysis
// Captures all HTTP/HTTPS traffic and sends to Python monitor

console.log("[*] Enhanced Network Capture Script Loaded");

// Import the analytics comprehensive spoof
load("frida-interception-and-unpinning/analytics-comprehensive-spoof.js");

if (ObjC.available) {
    console.log("[+] Adding Network Capture Enhancement...");
    
    var capturedRequests = [];
    var capturedResponses = {};
    var analyticsEvents = [];
    
    // Hook NSURLSession for comprehensive network capture
    try {
        // Capture request creation
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        
        Interceptor.attach(NSMutableURLRequest['- setHTTPBody:'].implementation, {
            onEnter: function(args) {
                var body = new ObjC.Object(args[2]);
                if (body && !body.isNull()) {
                    var bodyData = NSString.alloc().initWithData_encoding_(body, 4);
                    if (bodyData) {
                        var bodyString = bodyData.toString();
                        
                        // Check for analytics events
                        if (bodyString.includes("event") || bodyString.includes("analytics") || 
                            bodyString.includes("device_os_version")) {
                            
                            // Capture analytics event
                            var event = {
                                timestamp: Date.now(),
                                type: "analytics_event",
                                body: bodyString
                            };
                            
                            analyticsEvents.push(event);
                            
                            // Check for version inconsistency
                            var versionMatches = bodyString.match(/"(?:device_)?os_version"\s*:\s*"([^"]+)"/g);
                            if (versionMatches) {
                                versionMatches.forEach(function(match) {
                                    var version = match.match(/"([^"]+)"$/)[1];
                                    if (version !== "17.6.1") {
                                        console.log("[!] VERSION LEAK DETECTED: " + version);
                                        send({
                                            type: 'version_inconsistency',
                                            found: version,
                                            expected: "17.6.1",
                                            context: bodyString.substring(0, 200)
                                        });
                                    }
                                });
                            }
                        }
                        
                        // Send to Python monitor
                        send({
                            type: 'network_capture',
                            stage: 'request_body',
                            timestamp: Date.now(),
                            body: bodyString.substring(0, 5000) // Limit size
                        });
                    }
                }
            }
        });
    } catch(e) {
        console.log("[!] Failed to hook setHTTPBody: " + e);
    }
    
    // Capture all network responses
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        
        // Hook data task completion
        var dataTaskWithRequestCompletionHandler = NSURLSession['- dataTaskWithRequest:completionHandler:'];
        if (dataTaskWithRequestCompletionHandler) {
            Interceptor.attach(dataTaskWithRequestCompletionHandler.implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL().absoluteString().toString();
                    
                    // Store request details
                    this.requestId = Date.now() + "_" + Math.random();
                    this.url = url;
                    this.method = request.HTTPMethod().toString();
                    
                    // Capture request headers
                    var headers = {};
                    var headerDict = request.allHTTPHeaderFields();
                    if (headerDict && !headerDict.isNull()) {
                        var keys = headerDict.allKeys();
                        for (var i = 0; i < keys.count(); i++) {
                            var key = keys.objectAtIndex_(i).toString();
                            headers[key] = headerDict.objectForKey_(keys.objectAtIndex_(i)).toString();
                        }
                    }
                    
                    // Create wrapped completion handler
                    var originalHandler = new ObjC.Object(args[3]);
                    var requestId = this.requestId;
                    var captureUrl = this.url;
                    
                    var newHandler = ObjC.implement(originalHandler, {
                        'type:': function(data, response, error) {
                            // Capture response
                            var responseData = {
                                type: 'network_capture',
                                stage: 'response',
                                requestId: requestId,
                                url: captureUrl,
                                timestamp: Date.now()
                            };
                            
                            if (response && !response.isNull()) {
                                var httpResponse = new ObjC.Object(response);
                                responseData.statusCode = httpResponse.statusCode().valueOf();
                                
                                // Check for errors
                                if (responseData.statusCode >= 400) {
                                    console.log("[!] HTTP ERROR: " + responseData.statusCode + " for " + captureUrl);
                                }
                            }
                            
                            if (data && !data.isNull()) {
                                var responseString = NSString.alloc().initWithData_encoding_(data, 4);
                                if (responseString) {
                                    responseData.body = responseString.toString().substring(0, 5000);
                                    
                                    // Check for specific error patterns
                                    if (responseData.body.includes("ErrorNetworking") || 
                                        responseData.body.includes("ResponseStatusCodeError")) {
                                        console.log("[!] API ERROR DETECTED!");
                                        send({
                                            type: 'api_error',
                                            url: captureUrl,
                                            status: responseData.statusCode,
                                            body: responseData.body
                                        });
                                    }
                                }
                            }
                            
                            if (error && !error.isNull()) {
                                responseData.error = error.localizedDescription().toString();
                                console.log("[!] Network Error: " + responseData.error);
                            }
                            
                            // Send to Python monitor
                            send(responseData);
                            
                            // Call original handler
                            originalHandler['type:'](data, response, error);
                        }
                    });
                    
                    // Replace handler with our wrapped version
                    args[3] = newHandler;
                    
                    // Send request info
                    send({
                        type: 'network_capture',
                        stage: 'request',
                        requestId: this.requestId,
                        url: this.url,
                        method: this.method,
                        headers: headers,
                        timestamp: Date.now()
                    });
                }
            });
            console.log("[+] Network response capture hooked");
        }
    } catch(e) {
        console.log("[!] Failed to hook NSURLSession: " + e);
    }
    
    // Monitor for DoorDash-specific API calls
    try {
        // Look for DoorDash API endpoints
        var DDAPIManager = ObjC.classes.DDAPIManager;
        var DDNetworkManager = ObjC.classes.DDNetworkManager;
        var DDAnalyticsManager = ObjC.classes.DDAnalyticsManager;
        
        if (DDAPIManager) {
            console.log("[+] Found DoorDash API Manager");
            // Hook API calls
            var methods = DDAPIManager.$ownMethods;
            methods.forEach(function(method) {
                if (method.includes("request") || method.includes("dash")) {
                    Interceptor.attach(DDAPIManager[method].implementation, {
                        onEnter: function(args) {
                            console.log("[DD-API] " + method);
                        }
                    });
                }
            });
        }
        
        if (DDAnalyticsManager) {
            console.log("[+] Found DoorDash Analytics Manager");
            // Hook analytics events
            var methods = DDAnalyticsManager.$ownMethods;
            methods.forEach(function(method) {
                if (method.includes("track") || method.includes("event")) {
                    Interceptor.attach(DDAnalyticsManager[method].implementation, {
                        onEnter: function(args) {
                            console.log("[DD-Analytics] " + method);
                            // Try to get event details
                            for (var i = 2; i < args.length && i < 5; i++) {
                                try {
                                    var obj = new ObjC.Object(args[i]);
                                    if (obj) {
                                        console.log("  Arg[" + (i-2) + "]: " + obj.toString().substring(0, 100));
                                    }
                                } catch(e) {}
                            }
                        }
                    });
                }
            });
        }
    } catch(e) {
        console.log("[*] DoorDash-specific classes not found (may not be loaded yet)");
    }
    
    // Periodic status report
    setInterval(function() {
        var status = {
            type: 'status_report',
            timestamp: Date.now(),
            requests_captured: capturedRequests.length,
            analytics_events: analyticsEvents.length
        };
        send(status);
    }, 10000); // Every 10 seconds
    
    console.log("[+] Network Capture Enhancement Complete!");
    console.log("[+] Monitoring all network traffic...");
    console.log("[+] Python monitor will analyze in real-time");
    
} else {
    console.log("[!] Objective-C runtime not available");
}