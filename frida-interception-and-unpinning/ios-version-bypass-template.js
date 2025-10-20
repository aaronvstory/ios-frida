/**
 * iOS Version Bypass Template with Proxy Integration
 * Generated dynamically based on selected iOS version
 * Version: {{VERSION}}
 * CFNetwork: {{CFNETWORK}}
 * Darwin: {{DARWIN}}
 */

console.log("[+] iOS Version Bypass Loading...");
console.log("[+] Target Version: {{VERSION}}");
console.log("[+] CFNetwork: {{CFNETWORK}}");
console.log("[+] Darwin: {{DARWIN}}");

// Configuration from template
const TARGET_IOS = "{{VERSION}}";
const TARGET_CFNETWORK = "{{CFNETWORK}}";
const TARGET_DARWIN = "{{DARWIN}}";
const TARGET_BUILD = "{{BUILD}}";
const PROXY_HOST = "{{PROXY_HOST}}";
const PROXY_PORT = {{PROXY_PORT}};

// ============= iOS VERSION BYPASS =============
if (ObjC.available) {
    console.log("[+] Installing iOS version hooks...");

    // Hook UIDevice systemVersion - Primary version check
    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function (retval) {
                var original = new ObjC.Object(retval).toString();
                if (original !== TARGET_IOS) {
                    retval.replace(ObjC.classes.NSString.stringWithString_(TARGET_IOS));
                    console.log("[+] UIDevice.systemVersion: " + original + " -> " + TARGET_IOS);
                }
            }
        });
    } catch (e) {
        console.log("[-] UIDevice hook failed: " + e);
    }

    // Hook NSProcessInfo operatingSystemVersion
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;

        // operatingSystemVersion struct
        Interceptor.attach(NSProcessInfo['- operatingSystemVersion'].implementation, {
            onLeave: function (retval) {
                var versionPtr = new NativePointer(retval);

                // Parse target version
                var parts = TARGET_IOS.split(".");
                var major = parseInt(parts[0]) || 18;
                var minor = parseInt(parts[1]) || 0;
                var patch = parseInt(parts[2]) || 0;

                // Read current
                var currentMajor = versionPtr.readU64();
                var currentMinor = versionPtr.add(8).readU64();
                var currentPatch = versionPtr.add(16).readU64();

                if (currentMajor != major) {
                    versionPtr.writeU64(major);
                    versionPtr.add(8).writeU64(minor);
                    versionPtr.add(16).writeU64(patch);
                    console.log("[+] NSProcessInfo.operatingSystemVersion: " + currentMajor + "." + currentMinor + "." + currentPatch + " -> " + major + "." + minor + "." + patch);
                }
            }
        });

        // operatingSystemVersionString
        Interceptor.attach(NSProcessInfo['- operatingSystemVersionString'].implementation, {
            onLeave: function (retval) {
                var originalString = new ObjC.Object(retval).toString();
                if (!originalString.includes(TARGET_IOS)) {
                    var newVersionString = "Version " + TARGET_IOS + " (Build " + TARGET_BUILD + ")";
                    retval.replace(ObjC.classes.NSString.stringWithString_(newVersionString));
                    console.log("[+] OS Version String -> " + newVersionString);
                }
            }
        });

        // Force all version checks to pass
        Interceptor.attach(NSProcessInfo['- isOperatingSystemAtLeastVersion:'].implementation, {
            onEnter: function (args) {
                var versionPtr = new NativePointer(args[2]);
                var major = versionPtr.readU64();
                var minor = versionPtr.add(8).readU64();
                var patch = versionPtr.add(16).readU64();
                this.checkVersion = major + "." + minor + "." + patch;
            },
            onLeave: function (retval) {
                retval.replace(ptr(0x1)); // Always return YES
                console.log("[+] Version check for " + this.checkVersion + " -> PASSED (forced)");
            }
        });
    } catch (e) {
        console.log("[-] NSProcessInfo hooks failed: " + e);
    }

    // Hook User-Agent modifications - CRITICAL for network requests
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

        // Hook setValue:forHTTPHeaderField:
        Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'].implementation, {
            onEnter: function (args) {
                var field = new ObjC.Object(args[3]).toString();
                if (field.toLowerCase() === "user-agent") {
                    var value = new ObjC.Object(args[2]).toString();
                    var original = value;

                    // Update all version-related components
                    value = value.replace(/iOS \d+\.\d+(\.\d+)?/, "iOS " + TARGET_IOS);
                    value = value.replace(/CFNetwork\/[\d.]+/, "CFNetwork/" + TARGET_CFNETWORK);
                    value = value.replace(/Darwin\/[\d.]+/, "Darwin/" + TARGET_DARWIN);
                    value = value.replace(/\(iPhone[^;]*; iOS \d+\.\d+(\.\d+)?/, "(iPhone; iOS " + TARGET_IOS);

                    if (value !== original) {
                        args[2] = ObjC.classes.NSString.stringWithString_(value);
                        console.log("[+] User-Agent updated with iOS " + TARGET_IOS + " / CFNetwork " + TARGET_CFNETWORK);
                    }
                }
            }
        });

        // Hook allHTTPHeaderFields
        Interceptor.attach(NSMutableURLRequest['- allHTTPHeaderFields'].implementation, {
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var headers = new ObjC.Object(retval);
                    if (headers && headers.objectForKey_) {
                        var userAgent = headers.objectForKey_("User-Agent");
                        if (userAgent) {
                            var uaString = userAgent.toString();
                            var original = uaString;

                            uaString = uaString.replace(/iOS \d+\.\d+(\.\d+)?/, "iOS " + TARGET_IOS);
                            uaString = uaString.replace(/CFNetwork\/[\d.]+/, "CFNetwork/" + TARGET_CFNETWORK);
                            uaString = uaString.replace(/Darwin\/[\d.]+/, "Darwin/" + TARGET_DARWIN);

                            if (uaString !== original) {
                                var mutableHeaders = headers.mutableCopy();
                                mutableHeaders.setObject_forKey_(ObjC.classes.NSString.stringWithString_(uaString), "User-Agent");
                                retval.replace(mutableHeaders);
                                console.log("[+] Headers modified with version spoofing");
                            }
                        }
                    }
                }
            }
        });
    } catch (e) {
        console.log("[-] NSMutableURLRequest hooks failed: " + e);
    }

    // Hook URL query parameters for systemVersion
    try {
        var NSURLComponents = ObjC.classes.NSURLComponents;

        Interceptor.attach(NSURLComponents['- queryItems'].implementation, {
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var queryItems = new ObjC.Object(retval);
                    var itemsArray = queryItems.allObjects();
                    var modified = false;

                    for (var i = 0; i < itemsArray.count(); i++) {
                        var item = itemsArray.objectAtIndex_(i);
                        var name = item.name().toString();

                        if (name === "systemVersion" || name === "ios_version" || name === "osVersion") {
                            var value = item.value() ? item.value().toString() : "";
                            if (!value.includes(TARGET_IOS.split(".")[0])) {
                                var NSURLQueryItem = ObjC.classes.NSURLQueryItem;
                                var newItem = NSURLQueryItem.alloc().initWithName_value_(name, TARGET_IOS);

                                var mutableArray = queryItems.mutableCopy();
                                mutableArray.replaceObjectAtIndex_withObject_(i, newItem);
                                retval.replace(mutableArray);

                                console.log("[+] URL param " + name + ": " + value + " -> " + TARGET_IOS);
                                modified = true;
                            }
                        }
                    }
                }
            }
        });

        // Also hook NSURLRequest URL getter to modify URLs directly
        var NSURLRequest = ObjC.classes.NSURLRequest;
        Interceptor.attach(NSURLRequest['- URL'].implementation, {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    var url = new ObjC.Object(retval);
                    var urlString = url.absoluteString().toString();
                    var original = urlString;

                    // Replace version patterns in URL
                    urlString = urlString.replace(/systemVersion=\d+\.\d+(\.\d+)?/, "systemVersion=" + TARGET_IOS);
                    urlString = urlString.replace(/ios_version=\d+\.\d+(\.\d+)?/, "ios_version=" + TARGET_IOS);
                    urlString = urlString.replace(/osVersion=\d+\.\d+(\.\d+)?/, "osVersion=" + TARGET_IOS);

                    if (urlString !== original) {
                        var NSURL = ObjC.classes.NSURL;
                        var newUrl = NSURL.URLWithString_(urlString);
                        if (newUrl) {
                            retval.replace(newUrl);
                            console.log("[+] URL version params updated");
                        }
                    }
                }
            }
        });
    } catch (e) {
        console.log("[-] URL parameter hooks failed: " + e);
    }

    // Hook Bundle Info Dictionary for version spoofing
    try {
        var NSBundle = ObjC.classes.NSBundle;
        Interceptor.attach(NSBundle['- infoDictionary'].implementation, {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    var info = new ObjC.Object(retval);
                    var mutable = info.mutableCopy();

                    // Update system version keys
                    mutable.setObject_forKey_(ObjC.classes.NSString.stringWithString_(TARGET_IOS), "DTPlatformVersion");
                    mutable.setObject_forKey_(ObjC.classes.NSString.stringWithString_(TARGET_IOS), "MinimumOSVersion");

                    retval.replace(mutable);
                }
            }
        });
    } catch (e) {}
}

// ============= SSL PINNING BYPASS =============
console.log("[+] Installing SSL pinning bypass...");

// NSURLSession proxy configuration
if (ObjC.available) {
    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration'].forEach(function(method) {
            var original = NSURLSessionConfiguration[method];
            if (original) {
                NSURLSessionConfiguration[method] = function() {
                    var config = original.call(this);
                    config.setConnectionProxyDictionary_({
                        "HTTPEnable": 1,
                        "HTTPProxy": PROXY_HOST,
                        "HTTPPort": PROXY_PORT,
                        "HTTPSEnable": 1,
                        "HTTPSProxy": PROXY_HOST,
                        "HTTPSPort": PROXY_PORT
                    });
                    console.log("[+] Proxy configured: " + PROXY_HOST + ":" + PROXY_PORT);
                    return config;
                };
            }
        });
    } catch(e) {
        console.log("[-] Proxy configuration failed: " + e);
    }

    // SSL Trust bypass
    try {
        Interceptor.replace(Module.findExportByName(null, 'SecTrustEvaluate'), new NativeCallback(function(trust, result) {
            Memory.writePointer(result, ptr(0x1));
            return 0;
        }, 'int', ['pointer', 'pointer']));
    } catch(e) {}

    try {
        Interceptor.replace(Module.findExportByName(null, 'SecTrustEvaluateWithError'), new NativeCallback(function(trust, error) {
            if (!error.isNull()) {
                Memory.writePointer(error, ptr(0x0));
            }
            return 1;
        }, 'bool', ['pointer', 'pointer']));
    } catch(e) {}
}

// ============= MONITORING =============
if (ObjC.available) {
    // Monitor network requests
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        ['- dataTaskWithRequest:completionHandler:', '- dataTaskWithURL:completionHandler:'].forEach(function(method) {
            if (NSURLSession[method]) {
                Interceptor.attach(NSURLSession[method].implementation, {
                    onEnter: function(args) {
                        var request = new ObjC.Object(args[2]);
                        if (request.URL) {
                            var url = request.URL().absoluteString().toString();
                            if (url.includes("doordash") || url.includes("dasher")) {
                                console.log("[>] Request: " + url.substring(0, 100));
                            }
                        }
                    }
                });
            }
        });
    } catch(e) {}
}

console.log("==============================================");
console.log("[+] iOS Version Bypass Active!");
console.log("[+] Device spoofed as iOS " + TARGET_IOS);
console.log("[+] CFNetwork: " + TARGET_CFNETWORK);
console.log("[+] Darwin: " + TARGET_DARWIN);
console.log("[+] Proxy: " + PROXY_HOST + ":" + PROXY_PORT);
console.log("[+] SSL Pinning: BYPASSED");
console.log("==============================================");