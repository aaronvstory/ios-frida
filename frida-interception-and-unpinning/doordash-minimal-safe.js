// DoorDash Minimal Safe Bypass - Ultra-simple to prevent crashes
// Only the most essential spoofing with maximum stability

console.log("[*] Starting DoorDash Minimal Safe Bypass...");
console.log("[+] Ultra-lightweight for stability");

var spoofVersion = "17.6.1";
var spoofCFNetwork = "1490.0.4";
var spoofDarwin = "23.6.0";

if (ObjC.available) {

    setTimeout(function() {
        try {
            // Hook UIDevice systemVersion - Most important
            var UIDevice = ObjC.classes.UIDevice;
            var systemVersionMethod = UIDevice['- systemVersion'];

            if (systemVersionMethod) {
                Interceptor.attach(systemVersionMethod.implementation, {
                    onLeave: function(retval) {
                        try {
                            var fake = ObjC.classes.NSString.stringWithString_(spoofVersion);
                            retval.replace(fake);
                        } catch(e) {}
                    }
                });
                console.log("[+] iOS version hook installed: " + spoofVersion);
            }
        } catch(e) {
            console.log("[-] iOS version hook failed: " + e);
        }

        try {
            // Hook NSMutableURLRequest to add CFNetwork header
            var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

            // Only hook setValue:forHTTPHeaderField: which is safe
            var setValueMethod = NSMutableURLRequest['- setValue:forHTTPHeaderField:'];

            if (setValueMethod) {
                Interceptor.attach(setValueMethod.implementation, {
                    onEnter: function(args) {
                        try {
                            var field = ObjC.Object(args[3]);
                            if (field && field.toString() === "User-Agent") {
                                var value = ObjC.Object(args[2]);
                                if (value) {
                                    var str = value.toString();
                                    // Only modify if CFNetwork not already present
                                    if (str.indexOf("CFNetwork") === -1) {
                                        var newUA = str + " CFNetwork/" + spoofCFNetwork + " Darwin/" + spoofDarwin;
                                        args[2] = ObjC.classes.NSString.stringWithString_(newUA);
                                    }
                                }
                            }
                        } catch(e) {}
                    }
                });
                console.log("[+] User-Agent hook installed: CFNetwork/" + spoofCFNetwork);
            }
        } catch(e) {
            console.log("[-] User-Agent hook failed: " + e);
        }

    }, 500); // Small delay to let app initialize

    console.log("[+] DoorDash Minimal Safe Bypass loaded");
    console.log("[+] Spoofing iOS " + spoofVersion + " with CFNetwork " + spoofCFNetwork);
    console.log("[+] Minimal hooks for maximum stability");

} else {
    console.log("[-] Objective-C runtime not available");
}