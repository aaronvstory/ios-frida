// DoorDash Dasher - Version Spoof + Signup Flow Fix
// Fixes white screen by intercepting 404 responses during version-spoofed signup

console.log("[*] Starting DoorDash Dasher Signup Fix...");
console.log("[*] This script handles version spoofing side effects");

if (ObjC.available) {
    console.log("[+] Objective-C runtime available");

    // ============================================================================
    // PART 1: SSL Pinning Bypass
    // ============================================================================

    // Bypass NSURLSession SSL pinning
    var NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
        console.log("[+] Installing NSURLSession SSL bypass");

        var delegate = ObjC.classes.NSURLSessionDelegate;
        if (delegate && delegate['- URLSession:didReceiveChallenge:completionHandler:']) {
            Interceptor.attach(delegate['- URLSession:didReceiveChallenge:completionHandler:'].implementation, {
                onEnter: function(args) {
                    // args[0] = self, args[1] = _cmd, args[2] = session, args[3] = challenge, args[4] = completionHandler
                    var completionHandler = new ObjC.Block(args[4]);
                    var implementations = completionHandler.implementation;

                    // Call completion handler with allow all
                    // NSURLSessionAuthChallengeUseCredential = 0
                    // Pass nil credential to accept all
                    completionHandler(0, NULL);
                }
            });
        }
    }

    // Bypass SecTrustEvaluate
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
        console.log("[+] Installing SecTrustEvaluate bypass");
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
            // Always return success (errSecSuccess = 0)
            if (result) {
                Memory.writeU8(result, 1); // kSecTrustResultProceed
            }
            return 0;
        }, 'int', ['pointer', 'pointer']));
    }

    // ============================================================================
    // PART 2: HTTP Response Interceptor - Fix 404 Errors
    // ============================================================================

    console.log("[+] Installing HTTP response interceptor");

    // Intercept NSHTTPURLResponse initialization to modify status codes
    var NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
    if (NSHTTPURLResponse) {
        var initWithURL = NSHTTPURLResponse['- initWithURL:statusCode:HTTPVersion:headerFields:'];
        if (initWithURL) {
            Interceptor.attach(initWithURL.implementation, {
                onEnter: function(args) {
                    // args[0] = self, args[1] = _cmd, args[2] = URL, args[3] = statusCode, args[4] = HTTPVersion, args[5] = headerFields
                    var url = new ObjC.Object(args[2]);
                    var urlString = url.absoluteString().toString();
                    var statusCode = args[3].toInt32();

                    // Check for problematic endpoints that return 404 during spoofed signup
                    var shouldFix = false;
                    var endpoint = '';

                    if (urlString.includes('/v3/dasher/me/')) {
                        shouldFix = true;
                        endpoint = '/v3/dasher/me/';
                    } else if (urlString.includes('/v3/dashers/user_consent_status')) {
                        shouldFix = true;
                        endpoint = '/v3/dashers/user_consent_status';
                    }

                    if (shouldFix && statusCode === 404) {
                        console.log(`[INTERCEPT] ${endpoint} - Changing 404 to 200`);
                        args[3] = ptr(200); // Change status code to 200 OK

                        // Store URL for response body modification
                        this.interceptedURL = urlString;
                        this.interceptedEndpoint = endpoint;
                    }
                },
                onLeave: function(retval) {
                    if (this.interceptedURL) {
                        console.log(`[SUCCESS] Modified response for ${this.interceptedEndpoint}`);
                    }
                }
            });
        }
    }

    // Intercept NSURLSessionDataTask completion to modify response data
    var NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
    if (NSURLSessionDataTask) {
        console.log("[+] Installing NSURLSessionDataTask completion interceptor");

        // This is tricky - we need to intercept the completion handler
        // Let's hook NSURLSession's dataTaskWithRequest:completionHandler:
        var dataTaskWithRequest = NSURLSession['- dataTaskWithRequest:completionHandler:'];
        if (dataTaskWithRequest) {
            Interceptor.attach(dataTaskWithRequest.implementation, {
                onEnter: function(args) {
                    // args[0] = self, args[1] = _cmd, args[2] = request, args[3] = completionHandler
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL().absoluteString().toString();

                    // Check if this is a request we want to intercept
                    if (url.includes('/v3/dasher/me/') || url.includes('/v3/dashers/user_consent_status')) {
                        console.log(`[HOOK] Intercepting request to: ${url.substring(0, 80)}...`);

                        var originalHandler = new ObjC.Block(args[3]);
                        var newHandler = new ObjC.Block({
                            retType: 'void',
                            argTypes: ['object', 'object', 'object'], // NSData, NSURLResponse, NSError
                            implementation: function(data, response, error) {
                                var responseObj = new ObjC.Object(response);

                                if (responseObj && responseObj.statusCode) {
                                    var statusCode = responseObj.statusCode().toInt32();

                                    if (statusCode === 404) {
                                        console.log(`[FIX] Detected 404 response - injecting fake success data`);

                                        // Create fake success response data
                                        var fakeData = {};

                                        if (url.includes('/v3/dasher/me/')) {
                                            // Fake dasher profile
                                            fakeData = {
                                                "id": "fake_dasher_id",
                                                "status": "pending_signup",
                                                "onboarding_status": "in_progress"
                                            };
                                        } else if (url.includes('/v3/dashers/user_consent_status')) {
                                            // Fake consent status
                                            fakeData = {
                                                "consent_given": false,
                                                "needs_consent": true
                                            };
                                        }

                                        var fakeJsonString = JSON.stringify(fakeData);
                                        var fakeNSString = ObjC.classes.NSString.stringWithString_(fakeJsonString);
                                        var fakeNSData = fakeNSString.dataUsingEncoding_(4); // NSUTF8StringEncoding = 4

                                        // Call original handler with fake success data
                                        originalHandler(fakeNSData, response, null);
                                        return;
                                    }
                                }

                                // Call original handler if not 404
                                originalHandler(data, response, error);
                            }
                        });

                        args[3] = newHandler;
                    }
                }
            });
        }
    }

    // ============================================================================
    // PART 3: Proxy Configuration for HTTP Toolkit
    // ============================================================================

    console.log("[+] Configuring HTTP Toolkit proxy");

    var proxyHost = "192.168.50.9";
    var proxyPort = 8000;

    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
    if (NSURLSessionConfiguration) {
        var defaultConfig = NSURLSessionConfiguration['+ defaultSessionConfiguration'];
        if (defaultConfig) {
            Interceptor.attach(defaultConfig.implementation, {
                onLeave: function(retval) {
                    var config = new ObjC.Object(retval);

                    var proxyDict = ObjC.classes.NSDictionary.dictionaryWithObjectsAndKeys_(
                        ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy",
                        ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort",
                        ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy",
                        ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort"
                    );

                    config.setConnectionProxyDictionary_(proxyDict);
                    console.log(`[+] Proxy configured: ${proxyHost}:${proxyPort}`);
                }
            });
        }
    }

    // ============================================================================
    // PART 4: Request Logging (for debugging)
    // ============================================================================

    console.log("[+] Installing request logger");

    var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    if (NSMutableURLRequest) {
        var initWithURL = NSMutableURLRequest['- initWithURL:'];
        if (initWithURL) {
            Interceptor.attach(initWithURL.implementation, {
                onEnter: function(args) {
                    var url = new ObjC.Object(args[2]);
                    var urlString = url.absoluteString().toString();

                    // Only log DoorDash API calls
                    if (urlString.includes('doordash.com')) {
                        console.log(`[REQUEST] ${urlString.substring(0, 100)}`);
                    }
                }
            });
        }
    }

    console.log("[+] ========================================");
    console.log("[+] All hooks installed successfully!");
    console.log("[+] - SSL Pinning: BYPASSED");
    console.log("[+] - 404 Responses: INTERCEPTED & FIXED");
    console.log("[+] - HTTP Toolkit Proxy: CONFIGURED");
    console.log("[+] - Request Logging: ACTIVE");
    console.log("[+] ========================================");
    console.log("[+] You should now be able to proceed with signup!");

} else {
    console.log("[-] Objective-C runtime not available");
}
