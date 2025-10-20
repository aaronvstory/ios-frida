/**
 * DoorDash Dasher iOS Version Bypass Script
 * Bypasses iOS version checks to allow older devices to use the app
 * Targets: iOS 16.3.1 -> Spoofs as iOS 17.5.1
 */

console.log("[+] DoorDash iOS Version Bypass Script Loaded");
console.log("[+] Spoofing iOS 16.3.1 as iOS 17.5.1");

// Hook NSProcessInfo to spoof iOS version
if (ObjC.available) {
    try {
        // Hook operatingSystemVersionString
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        Interceptor.attach(NSProcessInfo['- operatingSystemVersionString'].implementation, {
            onLeave: function (retval) {
                var originalString = new ObjC.Object(retval).toString();
                console.log("[*] Original OS Version String: " + originalString);

                // Replace iOS 16.x with iOS 17.5.1
                var newVersionString = originalString.replace(/Version 16\.\d+(\.\d+)?/, "Version 17.5.1");
                newVersionString = newVersionString.replace(/\(Build \w+\)/, "(Build 21F79)");

                var newString = ObjC.classes.NSString.stringWithString_(newVersionString);
                retval.replace(newString);
                console.log("[+] Spoofed OS Version String: " + newVersionString);
            }
        });

        // Hook operatingSystemVersion struct
        Interceptor.attach(NSProcessInfo['- operatingSystemVersion'].implementation, {
            onLeave: function (retval) {
                // NSOperatingSystemVersion is a struct with majorVersion, minorVersion, patchVersion
                // Modify the struct to report iOS 17.5.1
                var versionPtr = new NativePointer(retval);

                // Read original values
                var major = versionPtr.readU64();
                var minor = versionPtr.add(8).readU64();
                var patch = versionPtr.add(16).readU64();

                console.log("[*] Original OS Version: " + major + "." + minor + "." + patch);

                // Write new values (17.5.1)
                versionPtr.writeU64(17);           // major
                versionPtr.add(8).writeU64(5);     // minor
                versionPtr.add(16).writeU64(1);    // patch

                console.log("[+] Spoofed OS Version: 17.5.1");
            }
        });

        // Hook isOperatingSystemAtLeastVersion
        Interceptor.attach(NSProcessInfo['- isOperatingSystemAtLeastVersion:'].implementation, {
            onEnter: function (args) {
                var versionPtr = new NativePointer(args[2]);
                var major = versionPtr.readU64();
                var minor = versionPtr.add(8).readU64();
                var patch = versionPtr.add(16).readU64();
                console.log("[?] Version Check: " + major + "." + minor + "." + patch);
            },
            onLeave: function (retval) {
                // Always return YES for version checks
                retval.replace(ptr(0x1));
                console.log("[+] Version Check: PASSED (forced)");
            }
        });

    } catch (e) {
        console.log("[-] Error hooking NSProcessInfo: " + e);
    }

    // Hook UIDevice to spoof system version
    try {
        var UIDevice = ObjC.classes.UIDevice;

        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function (retval) {
                var originalVersion = new ObjC.Object(retval).toString();
                console.log("[*] Original UIDevice systemVersion: " + originalVersion);

                // Return iOS 17.5.1
                var newVersion = ObjC.classes.NSString.stringWithString_("17.5.1");
                retval.replace(newVersion);
                console.log("[+] Spoofed UIDevice systemVersion: 17.5.1");
            }
        });

    } catch (e) {
        console.log("[-] Error hooking UIDevice: " + e);
    }

    // Hook CFNetwork/Darwin version in User-Agent
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

        Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'].implementation, {
            onEnter: function (args) {
                var value = new ObjC.Object(args[2]).toString();
                var field = new ObjC.Object(args[3]).toString();

                if (field.toLowerCase() === "user-agent") {
                    console.log("[*] Original User-Agent: " + value);

                    // Update CFNetwork and Darwin versions for iOS 17.5.1
                    var newUA = value.replace(/CFNetwork\/[\d.]+/, "CFNetwork/1485.0.5");
                    newUA = newUA.replace(/Darwin\/[\d.]+/, "Darwin/23.5.0");
                    newUA = newUA.replace(/iOS 16\.\d+(\.\d+)?/, "iOS 17.5.1");
                    newUA = newUA.replace(/\(iPhone; iOS 16\.\d+(\.\d+)?/, "(iPhone; iOS 17.5.1");

                    if (newUA !== value) {
                        var newUAString = ObjC.classes.NSString.stringWithString_(newUA);
                        args[2] = newUAString;
                        console.log("[+] Spoofed User-Agent: " + newUA);
                    }
                }
            }
        });

        // Also hook allHTTPHeaderFields getter
        Interceptor.attach(NSMutableURLRequest['- allHTTPHeaderFields'].implementation, {
            onLeave: function (retval) {
                var headers = new ObjC.Object(retval);
                if (headers && headers.objectForKey_) {
                    var userAgent = headers.objectForKey_("User-Agent");
                    if (userAgent) {
                        var uaString = userAgent.toString();
                        if (uaString.includes("iOS 16") || uaString.includes("CFNetwork/1404")) {
                            console.log("[*] Modifying headers in allHTTPHeaderFields");

                            var newUA = uaString.replace(/CFNetwork\/[\d.]+/, "CFNetwork/1485.0.5");
                            newUA = newUA.replace(/Darwin\/[\d.]+/, "Darwin/23.5.0");
                            newUA = newUA.replace(/iOS 16\.\d+(\.\d+)?/, "iOS 17.5.1");
                            newUA = newUA.replace(/\(iPhone; iOS 16\.\d+(\.\d+)?/, "(iPhone; iOS 17.5.1");

                            var mutableHeaders = headers.mutableCopy();
                            mutableHeaders.setObject_forKey_(ObjC.classes.NSString.stringWithString_(newUA), "User-Agent");
                            retval.replace(mutableHeaders);
                            console.log("[+] Headers modified successfully");
                        }
                    }
                }
            }
        });

    } catch (e) {
        console.log("[-] Error hooking NSMutableURLRequest: " + e);
    }

    // Hook URL query parameters to modify systemVersion
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
                        var value = item.value() ? item.value().toString() : "";

                        if (name === "systemVersion" && value.startsWith("16")) {
                            console.log("[*] Found systemVersion query param: " + value);

                            // Create new query item with iOS 17.5.1
                            var NSURLQueryItem = ObjC.classes.NSURLQueryItem;
                            var newItem = NSURLQueryItem.alloc().initWithName_value_("systemVersion", "17.5.1");

                            var mutableArray = queryItems.mutableCopy();
                            mutableArray.replaceObjectAtIndex_withObject_(i, newItem);
                            retval.replace(mutableArray);

                            console.log("[+] Modified systemVersion to: 17.5.1");
                            modified = true;
                            break;
                        }
                    }
                }
            }
        });

    } catch (e) {
        console.log("[-] Error hooking NSURLComponents: " + e);
    }

    // Hook any version comparison functions
    try {
        // Common version comparison method names
        var versionMethods = [
            '- compareVersion:',
            '- isVersion:greaterThan:',
            '- isVersion:greaterThanOrEqualTo:',
            '- minimumOSVersion',
            '- checkMinimumOSVersion'
        ];

        ObjC.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.includes("DoorDash") || className.includes("DD")) {
                    var clazz = ObjC.classes[className];
                    if (clazz) {
                        versionMethods.forEach(function(methodName) {
                            try {
                                if (clazz[methodName]) {
                                    Interceptor.attach(clazz[methodName].implementation, {
                                        onEnter: function(args) {
                                            console.log("[?] Version check in " + className + " " + methodName);
                                        },
                                        onLeave: function(retval) {
                                            // Force positive result for version checks
                                            if (methodName.includes("greater") || methodName.includes("minimum")) {
                                                retval.replace(ptr(0x1));
                                                console.log("[+] Forced version check to pass");
                                            }
                                        }
                                    });
                                }
                            } catch (e) {}
                        });
                    }
                }
            },
            onComplete: function() {}
        });

    } catch (e) {
        console.log("[-] Error hooking version methods: " + e);
    }

    console.log("[+] iOS Version Bypass hooks installed successfully!");
    console.log("[+] Device will appear as iOS 17.5.1 instead of iOS 16.3.1");

} else {
    console.log("[-] Objective-C runtime not available");
}