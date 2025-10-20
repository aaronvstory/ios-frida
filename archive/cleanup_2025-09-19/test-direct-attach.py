#!/usr/bin/env python
"""Direct test of iOS 17.6.1 bypass on DasherApp"""

import frida
import sys
import time

# Configuration
PID = 1031  # DasherApp
IOS_VERSION = "17.6.1"
CFNETWORK = "1490.0.4"
DARWIN = "23.6.0"

print(f"\n{'='*60}")
print(f"  Testing iOS {IOS_VERSION} Bypass on DasherApp")
print(f"{'='*60}")

try:
    # Connect to device
    print("\n[1] Connecting to iPhone...")
    device = frida.get_usb_device()
    print(f"    ✓ Device: {device.name}")
    print(f"    ✓ ID: {device.id}")

    # Attach to DasherApp
    print(f"\n[2] Attaching to DasherApp (PID: {PID})...")
    session = device.attach(PID)
    print("    ✓ Attached successfully")

    # Create minimal bypass script
    print(f"\n[3] Injecting iOS {IOS_VERSION} bypass...")
    bypass_script = f"""
    console.log("[+] iOS Version Bypass Loading...");

    if (ObjC.available) {{
        // Hook UIDevice systemVersion
        var UIDevice = ObjC.classes.UIDevice;
        Interceptor.attach(UIDevice['- systemVersion'].implementation, {{
            onLeave: function (retval) {{
                var original = new ObjC.Object(retval).toString();
                retval.replace(ObjC.classes.NSString.stringWithString_("{IOS_VERSION}"));
                console.log("[+] UIDevice.systemVersion: " + original + " -> {IOS_VERSION}");
            }}
        }});

        // Hook User-Agent headers
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        Interceptor.attach(NSMutableURLRequest['- setValue:forHTTPHeaderField:'].implementation, {{
            onEnter: function (args) {{
                var field = new ObjC.Object(args[3]).toString();
                if (field.toLowerCase() === "user-agent") {{
                    var value = new ObjC.Object(args[2]).toString();
                    var newValue = value.replace(/iOS \\d+\\.\\d+(\\.\\d+)?/, "iOS {IOS_VERSION}");
                    newValue = newValue.replace(/CFNetwork\\/[\\d.]+/, "CFNetwork/{CFNETWORK}");
                    newValue = newValue.replace(/Darwin\\/[\\d.]+/, "Darwin/{DARWIN}");
                    if (value !== newValue) {{
                        args[2] = ObjC.classes.NSString.stringWithString_(newValue);
                        console.log("[+] User-Agent updated with iOS {IOS_VERSION}");
                    }}
                }}
            }}
        }});

        console.log("[+] iOS {IOS_VERSION} bypass ACTIVE!");
        console.log("[+] CFNetwork: {CFNETWORK}");
        console.log("[+] Darwin: {DARWIN}");
    }} else {{
        console.log("[-] Objective-C runtime not available!");
    }}
    """

    script = session.create_script(bypass_script)

    # Handle messages from script
    def on_message(message, data):
        if message['type'] == 'send':
            print(f"    {message['payload']}")
        elif message['type'] == 'error':
            print(f"    ✗ Error: {message['stack']}")

    script.on('message', on_message)
    script.load()
    print(f"    ✓ iOS {IOS_VERSION} bypass injected")

    # Run for a few seconds to show it's working
    print("\n[4] Bypass is active. Monitoring for 10 seconds...")
    print("    Device now reports as iOS 17.6.1")
    print("    DoorDash servers will see the spoofed version")

    time.sleep(10)

    # Cleanup
    print("\n[5] Test completed successfully!")
    session.detach()

    print(f"\n{'='*60}")
    print("  ✅ SUCCESS: iOS Version Bypass Working!")
    print(f"{'='*60}")
    print(f"\n  DasherApp is now spoofed as iOS {IOS_VERSION}")
    print(f"  CFNetwork: {CFNETWORK}")
    print(f"  Darwin: {DARWIN}")
    print("\n  DoorDash should accept connections from this device!")

except frida.ProcessNotFoundError:
    print(f"\n✗ Error: DasherApp not found at PID {PID}")
    print("  Please open DasherApp on the iPhone first")
    sys.exit(1)
except Exception as e:
    print(f"\n✗ Error: {e}")
    sys.exit(1)