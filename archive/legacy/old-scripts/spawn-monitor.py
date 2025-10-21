#!/usr/bin/env python3
"""
Spawn Monitor - Restarts Dasher app with monitoring from the start
"""

import frida
import sys
import json
import time
from datetime import datetime

class SpawnMonitor:
    def __init__(self):
        self.bundle_id = "com.doordash.dasher"  # Dasher app bundle ID
        self.log_file = open('dasher-spawn-log.txt', 'w')
        self.captured_errors = []

    def on_message(self, message, data):
        """Handle messages from Frida script"""
        timestamp = datetime.now().strftime("%H:%M:%S")

        if message['type'] == 'send':
            payload = message.get('payload', '')

            # Write everything to log
            log_entry = f"[{timestamp}] {json.dumps(payload)}\n"
            self.log_file.write(log_entry)
            self.log_file.flush()

            # Display key info
            if isinstance(payload, dict):
                msg_type = payload.get('type', '')

                if msg_type == 'REQUEST':
                    url = payload.get('url', '')
                    if 'dash' in url.lower() or 'shift' in url.lower():
                        print(f"[{timestamp}] DASH REQUEST: {payload.get('method')} {url[:100]}")

                elif msg_type == 'ERROR':
                    print(f"[{timestamp}] ⚠️ ERROR: {payload.get('status')} - {payload.get('body', '')[:200]}")
                    self.captured_errors.append(payload)

                elif 'console' in msg_type.lower():
                    print(f"[{timestamp}] {payload.get('message', payload)}")
            else:
                # Regular console output
                if 'error' in str(payload).lower():
                    print(f"[{timestamp}] ERROR: {payload}")
                elif 'dash' in str(payload).lower():
                    print(f"[{timestamp}] DASH: {payload}")
                else:
                    print(f"[{timestamp}] {payload}")

    def run(self):
        print("="*80)
        print("SPAWN MONITOR - DASHER APP")
        print("="*80)

        # Connect to device
        print("\n[*] Connecting to USB device...")
        try:
            device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to: {device.name}")
        except Exception as e:
            print(f"[!] Failed to connect: {e}")
            return False

        # Minimal monitoring script
        script_code = """
        console.log("[SPAWN] Monitor injected successfully");

        if (ObjC.available) {
            // Hook NSURLSession for network monitoring
            dispatch_async(dispatch_get_main_queue(), function() {
                try {
                    var NSURLSession = ObjC.classes.NSURLSession;

                    // Hook all network requests
                    var dataTask = NSURLSession['- dataTaskWithRequest:completionHandler:'];
                    if (dataTask) {
                        Interceptor.attach(dataTask.implementation, {
                            onEnter: function(args) {
                                var request = new ObjC.Object(args[2]);
                                var url = request.URL().absoluteString().toString();

                                send({
                                    type: 'REQUEST',
                                    url: url,
                                    method: request.HTTPMethod() ? request.HTTPMethod().toString() : 'GET'
                                });

                                // Hook the completion handler
                                var handler = new ObjC.Block(args[3]);
                                var original = handler.implementation;

                                handler.implementation = function(data, response, error) {
                                    if (response) {
                                        var resp = new ObjC.Object(response);
                                        var status = resp.statusCode();

                                        if (status >= 400) {
                                            var body = '';
                                            if (data) {
                                                try {
                                                    var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                                    body = str ? str.toString() : '';
                                                } catch(e) {}
                                            }

                                            send({
                                                type: 'ERROR',
                                                url: url,
                                                status: status.toString(),
                                                body: body
                                            });
                                        }
                                    }

                                    return original(data, response, error);
                                };
                            }
                        });
                        console.log("[SPAWN] Network hooks installed");
                    }

                    // Basic iOS spoof
                    var UIDevice = ObjC.classes.UIDevice;
                    Interceptor.attach(UIDevice['- systemVersion'].implementation, {
                        onLeave: function(retval) {
                            retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
                        }
                    });
                    console.log("[SPAWN] iOS spoofed to 17.6.1");

                } catch(e) {
                    console.error("[SPAWN] Hook error: " + e);
                }
            });
        }
        """

        # Spawn the app with monitoring
        print(f"\n[*] Spawning {self.bundle_id} with monitoring...")
        try:
            pid = device.spawn([self.bundle_id])
            print(f"[+] App spawned with PID: {pid}")

            session = device.attach(pid)
            print("[+] Attached to spawned app")

            script = session.create_script(script_code)
            script.on('message', self.on_message)
            script.load()
            print("[+] Monitoring script loaded")

            # Resume the app
            device.resume(pid)
            print("[+] App resumed and running")

        except Exception as e:
            print(f"[!] Failed to spawn: {e}")
            print("\nTrying alternative bundle IDs...")

            # Try alternative bundle IDs
            alternatives = [
                "com.doordash.dasher",
                "com.doordash.DasherApp",
                "com.doordash.Dasher",
                "doordash.dasher"
            ]

            for alt_id in alternatives:
                try:
                    print(f"  Trying: {alt_id}")
                    pid = device.spawn([alt_id])
                    print(f"  ✓ Success with {alt_id}!")
                    self.bundle_id = alt_id

                    session = device.attach(pid)
                    script = session.create_script(script_code)
                    script.on('message', self.on_message)
                    script.load()
                    device.resume(pid)
                    break

                except:
                    continue
            else:
                print("[!] Could not spawn app with any bundle ID")
                return False

        # Monitor
        print("\n" + "="*80)
        print("MONITORING ACTIVE - APP IS RESTARTING")
        print("="*80)
        print("\n1. Wait for app to fully load")
        print("2. Log in if needed")
        print("3. Navigate to Dash Now")
        print("4. Tap 'Dash Now'")
        print("5. Press ENTER after you see the error")
        print("\n" + "="*80 + "\n")

        try:
            input()  # Wait for Enter
        except KeyboardInterrupt:
            print("\n[*] Interrupted")

        # Show captured errors
        if self.captured_errors:
            print("\n" + "="*80)
            print(f"CAPTURED {len(self.captured_errors)} ERRORS:")
            print("="*80)
            for err in self.captured_errors:
                print(f"\nStatus: {err.get('status')}")
                print(f"URL: {err.get('url')}")
                print(f"Body: {err.get('body', 'No body')[:500]}")
                print("-"*40)

        # Cleanup
        print("\n[*] Stopping monitor...")
        try:
            script.unload()
            session.detach()
        except:
            pass

        self.log_file.close()
        print("[+] Full log saved to dasher-spawn-log.txt")
        return True

def main():
    monitor = SpawnMonitor()
    monitor.run()

if __name__ == "__main__":
    main()