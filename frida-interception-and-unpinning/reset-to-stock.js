// Reset to Stock - Remove all hooks and restore original behavior
// This script attempts to clean up and restore stock iOS behavior

console.log("[*] Starting Reset to Stock...");

if (ObjC.available) {
    console.log("[+] Removing all Frida hooks...");

    // Detach all interceptors
    try {
        Interceptor.detachAll();
        console.log("[+] All interceptors detached");
    } catch(e) {
        console.log("[-] Error detaching interceptors: " + e);
    }

    // Clear any proxy configurations
    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

        // Reset default configuration
        var defaultConfig = NSURLSessionConfiguration.defaultSessionConfiguration();
        if (defaultConfig) {
            defaultConfig.setConnectionProxyDictionary_(null);
            console.log("[+] Cleared proxy from default session");
        }

        // Reset ephemeral configuration
        var ephemeralConfig = NSURLSessionConfiguration.ephemeralSessionConfiguration();
        if (ephemeralConfig) {
            ephemeralConfig.setConnectionProxyDictionary_(null);
            console.log("[+] Cleared proxy from ephemeral session");
        }
    } catch(e) {}

    // Force garbage collection
    if (typeof gc !== 'undefined') {
        gc();
    }

    console.log("[+] Reset complete!");
    console.log("[+] Device restored to stock behavior");

    // Attempt to terminate the app for complete reset
    try {
        console.log("[*] Attempting to terminate app for complete reset...");

        // Method 1: Try UIApplication.terminate (iOS 4.0+)
        try {
            var UIApplication = ObjC.classes.UIApplication;
            if (UIApplication && UIApplication.sharedApplication) {
                var app = UIApplication.sharedApplication();
                if (app && app.respondsToSelector_("terminate:")) {
                    console.log("[*] Using UIApplication.terminate...");
                    app.terminate_(null);
                    console.log("[+] App termination requested via UIApplication");
                }
            }
        } catch(e) {
            console.log("[-] UIApplication.terminate failed: " + e);
        }

        // Method 2: Try exit() function
        try {
            console.log("[*] Using exit() function...");
            var exit = new NativeFunction(Module.findExportByName(null, "exit"), 'void', ['int']);
            if (exit) {
                console.log("[+] App termination requested via exit()");
                exit(0);
            }
        } catch(e) {
            console.log("[-] exit() failed: " + e);
        }

        // Method 3: Try abort() function
        try {
            console.log("[*] Using abort() function...");
            var abort = new NativeFunction(Module.findExportByName(null, "abort"), 'void', []);
            if (abort) {
                console.log("[+] App termination requested via abort()");
                abort();
            }
        } catch(e) {
            console.log("[-] abort() failed: " + e);
        }

        // Method 4: Try NSThread.exit (thread-level termination)
        try {
            var NSThread = ObjC.classes.NSThread;
            if (NSThread && NSThread.exit) {
                console.log("[*] Using NSThread.exit...");
                NSThread.exit();
                console.log("[+] Thread termination requested via NSThread");
            }
        } catch(e) {
            console.log("[-] NSThread.exit failed: " + e);
        }

        // Method 5: Try Process.kill with current PID
        try {
            console.log("[*] Using Process.kill with current PID...");
            var getpid = new NativeFunction(Module.findExportByName(null, "getpid"), 'int', []);
            var kill = new NativeFunction(Module.findExportByName(null, "kill"), 'int', ['int', 'int']);

            if (getpid && kill) {
                var pid = getpid();
                console.log("[*] Current PID: " + pid);
                console.log("[+] Sending SIGTERM to current process");
                kill(pid, 15); // SIGTERM

                // If SIGTERM doesn't work, try SIGKILL after a brief delay
                setTimeout(function() {
                    console.log("[+] Sending SIGKILL to current process");
                    kill(pid, 9); // SIGKILL
                }, 100);
            }
        } catch(e) {
            console.log("[-] Process.kill failed: " + e);
        }

    } catch(e) {
        console.log("[-] App termination failed: " + e);
        console.log("[!] Manual app restart required");
    }

    // Send signal to detach (this may not reach if app terminates)
    send({type: 'reset_complete', termination_attempted: true});

} else {
    console.log("[!] Objective-C runtime not available");
}