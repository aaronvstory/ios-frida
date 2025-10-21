#!/usr/bin/env python3
"""
Direct Dasher Monitor - Robust version that won't crash
"""

import frida
import sys
import json
import time
from datetime import datetime

class DasherMonitor:
    def __init__(self):
        self.log_file = open('dasher-capture.log', 'w')
        self.request_count = 0
        self.error_count = 0

    def on_message(self, message, data):
        """Handle messages from Frida script"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if message['type'] == 'send':
            payload = message.get('payload', '')

            # Write to file
            self.log_file.write(f"[{timestamp}] {json.dumps(payload)}\n")
            self.log_file.flush()

            # Display based on type
            if isinstance(payload, dict):
                msg_type = payload.get('type', '')

                if msg_type == 'REQUEST':
                    self.request_count += 1
                    print(f"[{timestamp}] → REQUEST #{self.request_count}: {payload.get('method')} {payload.get('url', '')[:80]}")

                elif msg_type == 'RESPONSE':
                    status = payload.get('status', '?')
                    if int(status) >= 400:
                        self.error_count += 1
                        print(f"[{timestamp}] ← ERROR RESPONSE: {status} from {payload.get('url', '')[:80]}")
                    else:
                        print(f"[{timestamp}] ← RESPONSE: {status}")

                elif msg_type == 'ERROR_RESPONSE':
                    print(f"[{timestamp}] ⚠ ERROR DETAILS: {payload.get('body', '')[:200]}")

                elif msg_type == 'NETWORK_ERROR':
                    print(f"[{timestamp}] ❌ NETWORK ERROR: {payload.get('error', '')}")

                else:
                    print(f"[{timestamp}] {payload}")
            else:
                print(f"[{timestamp}] {payload}")

        elif message['type'] == 'error':
            print(f"[{timestamp}] SCRIPT ERROR: {message.get('description', 'Unknown error')}")
            self.log_file.write(f"[{timestamp}] ERROR: {message}\n")
            self.log_file.flush()

    def run(self):
        print("="*80)
        print("DIRECT DASHER MONITOR")
        print("="*80)

        # Connect to device
        print("\n[*] Connecting to USB device...")
        try:
            device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to: {device.name}")
        except Exception as e:
            print(f"[!] Failed to connect: {e}")
            return False

        # Find DasherApp
        print("\n[*] Looking for DasherApp...")
        try:
            processes = device.enumerate_processes()
            dasher_pid = None

            for proc in processes:
                if 'dasherapp' in proc.name.lower():
                    dasher_pid = proc.pid
                    print(f"[+] Found DasherApp: PID {proc.pid}")
                    break

            if not dasher_pid:
                # Show all dash-related processes
                print("\nDash-related processes found:")
                dash_procs = []
                for proc in processes:
                    if 'dash' in proc.name.lower():
                        dash_procs.append(proc)
                        print(f"  [{len(dash_procs)}] {proc.name} (PID: {proc.pid})")

                if dash_procs:
                    print("\nWhich one is the main Dasher app?")
                    choice = input("Enter number or PID: ").strip()

                    try:
                        if choice.isdigit() and len(choice) < 3:
                            # User entered a number
                            idx = int(choice) - 1
                            if 0 <= idx < len(dash_procs):
                                dasher_pid = dash_procs[idx].pid
                        else:
                            # User entered a PID
                            dasher_pid = int(choice)
                    except:
                        print("[!] Invalid input")
                        return False
                else:
                    print("[!] No Dash-related apps found!")
                    return False

        except Exception as e:
            print(f"[!] Error finding processes: {e}")
            return False

        # Attach to DasherApp
        print(f"\n[*] Attaching to PID {dasher_pid}...")
        try:
            session = device.attach(dasher_pid)
            print("[+] Attached successfully!")
        except Exception as e:
            print(f"[!] Failed to attach: {e}")
            return False

        # Monitoring script with error handling
        script_code = """
        console.log("[MONITOR] Script starting...");

        // Wrap everything in try-catch
        try {
            if (typeof ObjC !== 'undefined' && ObjC.available) {
                console.log("[MONITOR] ObjC available, installing hooks...");

                // Hook NSURLSession
                var NSURLSession = ObjC.classes.NSURLSession;
                if (NSURLSession) {
                    var dataTaskMethod = NSURLSession['- dataTaskWithRequest:completionHandler:'];

                    if (dataTaskMethod) {
                        Interceptor.attach(dataTaskMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    var request = new ObjC.Object(args[2]);
                                    var url = request.URL().absoluteString().toString();
                                    var method = request.HTTPMethod();

                                    send({
                                        type: 'REQUEST',
                                        method: method ? method.toString() : 'GET',
                                        url: url
                                    });

                                    // Try to get body
                                    var body = request.HTTPBody();
                                    if (body) {
                                        try {
                                            var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
                                            if (bodyStr) {
                                                send({
                                                    type: 'REQUEST_BODY',
                                                    body: bodyStr.toString().substring(0, 300)
                                                });
                                            }
                                        } catch(e) {}
                                    }

                                    // Hook response handler
                                    var handler = new ObjC.Block(args[3]);
                                    var oldImpl = handler.implementation;

                                    handler.implementation = function(data, response, error) {
                                        try {
                                            if (response) {
                                                var resp = new ObjC.Object(response);
                                                var status = resp.statusCode();

                                                send({
                                                    type: 'RESPONSE',
                                                    url: url,
                                                    status: status.toString()
                                                });

                                                // Capture error responses
                                                if (status >= 400 && data) {
                                                    try {
                                                        var respBody = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                                        if (respBody) {
                                                            send({
                                                                type: 'ERROR_RESPONSE',
                                                                status: status.toString(),
                                                                body: respBody.toString()
                                                            });
                                                        }
                                                    } catch(e) {}
                                                }
                                            }

                                            if (error) {
                                                send({
                                                    type: 'NETWORK_ERROR',
                                                    error: error.localizedDescription().toString()
                                                });
                                            }
                                        } catch(e) {
                                            console.log("[MONITOR] Response handler error: " + e);
                                        }

                                        return oldImpl(data, response, error);
                                    };
                                } catch(e) {
                                    console.log("[MONITOR] Request hook error: " + e);
                                }
                            }
                        });

                        console.log("[MONITOR] Network hooks installed successfully");
                    } else {
                        console.log("[MONITOR] dataTaskWithRequest method not found");
                    }
                } else {
                    console.log("[MONITOR] NSURLSession not found");
                }

                // Basic iOS spoof
                try {
                    var UIDevice = ObjC.classes.UIDevice;
                    if (UIDevice) {
                        var systemVersion = UIDevice['- systemVersion'];
                        if (systemVersion) {
                            Interceptor.attach(systemVersion.implementation, {
                                onLeave: function(retval) {
                                    retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
                                }
                            });
                            console.log("[MONITOR] iOS spoofed to 17.6.1");
                        }
                    }
                } catch(e) {
                    console.log("[MONITOR] Spoof error: " + e);
                }

            } else {
                console.log("[MONITOR] ObjC not available!");
            }
        } catch(e) {
            console.error("[MONITOR] Fatal error: " + e);
        }

        console.log("[MONITOR] Ready - tap Dash Now when ready");
        """

        # Load script
        print("\n[*] Loading monitoring script...")
        try:
            script = session.create_script(script_code)
            script.on('message', self.on_message)
            script.load()
            print("[+] Script loaded successfully!")
        except Exception as e:
            print(f"[!] Failed to load script: {e}")
            return False

        # Monitor
        print("\n" + "="*80)
        print("MONITORING ACTIVE - TAP 'DASH NOW' IN THE APP")
        print("="*80)
        print("\nI'm watching all network traffic now.")
        print("Please tap 'Dash Now' and wait for the error.")
        print("Press ENTER after you see the error...")
        print("="*80 + "\n")

        try:
            input()  # Wait for Enter
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")

        # Cleanup
        print(f"\n[*] Captured {self.request_count} requests, {self.error_count} errors")
        print("[*] Stopping monitor...")

        try:
            script.unload()
            session.detach()
        except:
            pass

        self.log_file.close()
        print("[+] Log saved to dasher-capture.log")

        return True

def main():
    monitor = DasherMonitor()
    success = monitor.run()

    if success:
        print("\n[+] Monitor session complete")
    else:
        print("\n[!] Monitor session failed")

if __name__ == "__main__":
    main()