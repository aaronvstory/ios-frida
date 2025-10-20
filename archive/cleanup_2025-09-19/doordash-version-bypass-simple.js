/**
 * DoorDash Simple iOS Version Bypass
 * Minimal hooks to bypass iOS version checks
 */

console.log("[+] DoorDash Simple Version Bypass Loading...");

if (ObjC.available) {
    // Hook UIDevice systemVersion - Most common check
    try {
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {
            onLeave: function (retval) {
                var newVersion = ObjC.classes.NSString.stringWithString_("18.0");
                retval.replace(newVersion);
                console.log("[+] UIDevice.systemVersion -> 18.0");
            }
        });
    } catch (e) {
        console.log("[-] UIDevice hook failed: " + e);
    }

    // Hook NSProcessInfo operatingSystemVersion
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        Interceptor.attach(NSProcessInfo['- operatingSystemVersion'].implementation, {
            onLeave: function (retval) {
                var versionPtr = new NativePointer(retval);
                versionPtr.writeU64(18);        // major
                versionPtr.add(8).writeU64(0);  // minor
                versionPtr.add(16).writeU64(0); // patch
                console.log("[+] NSProcessInfo.operatingSystemVersion -> 18.0.0");
            }
        });
    } catch (e) {
        console.log("[-] NSProcessInfo hook failed: " + e);
    }

    // Hook URL requests to modify systemVersion parameter
    try {
        var NSURLRequest = ObjC.classes.NSURLRequest;
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

        // Hook URL getter
        Interceptor.attach(NSURLRequest['- URL'].implementation, {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    var url = new ObjC.Object(retval);
                    var urlString = url.absoluteString().toString();

                    // Check if URL contains systemVersion parameter
                    if (urlString.includes("systemVersion=16")) {
                        console.log("[*] Found iOS 16 in URL: " + urlString);

                        // Replace iOS 16.x.x with 18.0
                        var newUrlString = urlString.replace(/systemVersion=16\.\d+(\.\d+)?/, "systemVersion=18.0");

                        if (newUrlString !== urlString) {
                            var NSURL = ObjC.classes.NSURL;
                            var newUrl = NSURL.URLWithString_(newUrlString);
                            retval.replace(newUrl);
                            console.log("[+] Modified URL systemVersion to 18.0");
                        }
                    }
                }
            }
        });

        // Hook User-Agent header
        Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'].implementation, {
            onEnter: function (args) {
                var field = new ObjC.Object(args[3]).toString();
                if (field.toLowerCase() === "user-agent") {
                    var value = new ObjC.Object(args[2]).toString();

                    // Replace iOS 16.x with iOS 18.0
                    var newUA = value.replace(/iOS 16\.\d+(\.\d+)?/, "iOS 18.0");
                    newUA = newUA.replace(/CFNetwork\/1404\.\d+(\.\d+)?/, "CFNetwork/1485.0.5");
                    newUA = newUA.replace(/Darwin\/22\.\d+(\.\d+)?/, "Darwin/24.0.0");

                    if (newUA !== value) {
                        args[2] = ObjC.classes.NSString.stringWithString_(newUA);
                        console.log("[+] Modified User-Agent to iOS 18.0");
                    }
                }
            }
        });

    } catch (e) {
        console.log("[-] NSURLRequest hooks failed: " + e);
    }

    // Force all version checks to pass
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        Interceptor.attach(NSProcessInfo['- isOperatingSystemAtLeastVersion:'].implementation, {
            onLeave: function (retval) {
                retval.replace(ptr(0x1)); // Always return YES
                console.log("[+] Version check forced to PASS");
            }
        });
    } catch (e) {
        console.log("[-] Version check bypass failed: " + e);
    }

    console.log("[+] Simple version bypass active - Device appears as iOS 18.0");
}