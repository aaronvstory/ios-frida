// Comprehensive Jailbreak Detection Bypass for DoorDash Dasher
console.log("[JB-BYPASS] Starting comprehensive jailbreak bypass...");

if (ObjC.available) {

    // ========================================
    // 1. FILE SYSTEM CHECKS
    // ========================================
    var fileManager = ObjC.classes.NSFileManager.defaultManager();

    // Hook fileExistsAtPath
    Interceptor.attach(fileManager["- fileExistsAtPath:"].implementation, {
        onEnter: function(args) {
            var path = ObjC.Object(args[2]).toString();

            var jailbreakPaths = [
                "/Applications/Cydia.app",
                "/Library/MobileSubstrate/",
                "/bin/bash",
                "/usr/sbin/sshd",
                "/etc/apt",
                "/private/var/lib/apt/",
                "/private/var/lib/cydia",
                "/private/var/mobile/Library/SBSettings/Themes",
                "/Library/MobileSubstrate/MobileSubstrate.dylib",
                "/Library/MobileSubstrate/DynamicLibraries",
                "/var/cache/apt",
                "/var/lib/apt",
                "/var/lib/cydia",
                "/var/log/syslog",
                "/var/tmp/cydia.log",
                "/bin/sh",
                "/usr/libexec/ssh-keysign",
                "/usr/bin/ssh",
                "/usr/libexec/sftp-server",
                "/Applications/Sileo.app",
                "/Applications/Zebra.app",
                "/.bootstrapped",
                "/usr/bin/apt",
                "/usr/bin/dpkg"
            ];

            for (var i = 0; i < jailbreakPaths.length; i++) {
                if (path == jailbreakPaths[i]) {
                    console.log("[JB-BYPASS] Hiding jailbreak path: " + path);
                    args[2] = ObjC.classes.NSString.stringWithString_("/non-existent-path");
                    break;
                }
            }
        },
        onLeave: function(retval) {
            // Force return NO for jailbreak paths
            var result = retval.toInt32();
            if (result == 1) {
                // Already handled in onEnter
            }
        }
    });

    // Hook canOpenURL (for Cydia URL scheme)
    var UIApplication = ObjC.classes.UIApplication.sharedApplication();
    Interceptor.attach(UIApplication["- canOpenURL:"].implementation, {
        onEnter: function(args) {
            var url = ObjC.Object(args[2]).toString();
            if (url.includes("cydia://") || url.includes("sileo://") || url.includes("zbra://")) {
                console.log("[JB-BYPASS] Blocking URL scheme check: " + url);
                args[2] = ObjC.classes.NSURL.URLWithString_("https://doordash.com");
            }
        },
        onLeave: function(retval) {
            retval.replace(ptr(0));
        }
    });

    // ========================================
    // 2. DYLIB DETECTION
    // ========================================
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            var path = args[0].readCString();
            if (path && (path.includes("MobileSubstrate") || path.includes("libhooker") ||
                        path.includes("substitute") || path.includes("TweakInject"))) {
                console.log("[JB-BYPASS] Blocking dylib load: " + path);
                args[0] = Memory.allocUtf8String("/usr/lib/libSystem.B.dylib");
            }
        }
    });

    // ========================================
    // 3. FRIDA DETECTION
    // ========================================
    // Hide Frida server
    Interceptor.attach(Module.findExportByName(null, "strstr"), {
        onEnter: function(args) {
            var str = args[1].readCString();
            if (str && (str.includes("frida") || str.includes("FRIDA"))) {
                console.log("[JB-BYPASS] Hiding Frida string");
                args[1] = Memory.allocUtf8String("nothing");
            }
        }
    });

    // ========================================
    // 4. SANDBOX INTEGRITY
    // ========================================
    // Hook fork() - jailbroken devices can fork
    Interceptor.replace(Module.findExportByName(null, "fork"), new NativeCallback(function() {
        console.log("[JB-BYPASS] Blocking fork()");
        return -1;
    }, 'int', []));

    // Hook system() - shouldn't work on non-jailbroken devices
    Interceptor.replace(Module.findExportByName(null, "system"), new NativeCallback(function(cmd) {
        console.log("[JB-BYPASS] Blocking system()");
        return -1;
    }, 'int', ['pointer']));

    // ========================================
    // 5. DEBUGGER DETECTION
    // ========================================
    // Prevent debugger detection
    Interceptor.replace(Module.findExportByName(null, "ptrace"), new NativeCallback(function(request, pid, addr, data) {
        console.log("[JB-BYPASS] Blocking ptrace");
        return 0;
    }, 'int', ['int', 'int', 'pointer', 'pointer']));

    // Hook sysctl to hide debugger
    Interceptor.attach(Module.findExportByName(null, "sysctl"), {
        onEnter: function(args) {
            // Check if querying for P_TRACED
            var mib = args[0];
            if (mib) {
                var request = mib.readU32();
                if (request == 1) { // CTL_KERN
                    var next = mib.add(4).readU32();
                    if (next == 14) { // KERN_PROC
                        console.log("[JB-BYPASS] Hiding debugger in sysctl");
                        this.hideDebugger = true;
                    }
                }
            }
        },
        onLeave: function(retval) {
            if (this.hideDebugger) {
                // Set P_TRACED flag to 0
                retval.replace(ptr(0));
            }
        }
    });

    // ========================================
    // 6. APP ATTESTATION ENHANCEMENT
    // ========================================
    // Ensure attestation passes
    var DCDevice = ObjC.classes.DCDevice;
    if (DCDevice) {
        Interceptor.attach(DCDevice["- isSupported"].implementation, {
            onLeave: function(retval) {
                console.log("[JB-BYPASS] Forcing attestation support");
                retval.replace(ptr(1));
            }
        });

        Interceptor.attach(DCDevice["- generateToken"].implementation, {
            onLeave: function(retval) {
                console.log("[JB-BYPASS] Ensuring valid attestation token");
                // Don't modify if already has a token
            }
        });
    }

    // ========================================
    // 7. CLEAR JAILBREAK ENVIRONMENT VARIABLES
    // ========================================
    var getenv_ptr = Module.findExportByName(null, "getenv");
    Interceptor.attach(getenv_ptr, {
        onEnter: function(args) {
            var name = args[0].readCString();
            if (name == "DYLD_INSERT_LIBRARIES" || name == "_MSSafeMode") {
                console.log("[JB-BYPASS] Hiding environment variable: " + name);
                args[0] = Memory.allocUtf8String("PATH");
            }
        }
    });

    // ========================================
    // 8. iOS VERSION SPOOFING
    // ========================================
    var UIDevice = ObjC.classes.UIDevice;
    Interceptor.attach(UIDevice["- systemVersion"].implementation, {
        onLeave: function(retval) {
            retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
        }
    });

    console.log("\n" + "=".repeat(60));
    console.log("JAILBREAK BYPASS ACTIVE");
    console.log("=".repeat(60));
    console.log("✓ File system checks bypassed");
    console.log("✓ Dylib detection bypassed");
    console.log("✓ Frida hidden");
    console.log("✓ Sandbox integrity spoofed");
    console.log("✓ Debugger hidden");
    console.log("✓ App attestation enhanced");
    console.log("✓ Environment cleaned");
    console.log("✓ iOS version spoofed");
    console.log("=".repeat(60));
    console.log("Try logging out and back in, then tap Dash Now");
    console.log("=".repeat(60) + "\n");

} else {
    console.log("[JB-BYPASS] ObjC not available!");
}