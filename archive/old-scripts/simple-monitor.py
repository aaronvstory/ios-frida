#!/usr/bin/env python3
"""
Simple Direct Dasher Monitor - No timeouts, direct PID attachment
"""

import frida
import sys
import json
from datetime import datetime

def on_message(message, data):
    """Handle messages from Frida script"""
    timestamp = datetime.now().strftime("%H:%M:%S")

    if message['type'] == 'send':
        payload = message.get('payload', '')
        print(f"[{timestamp}] {payload}")

        # Save to file for analysis
        with open('dasher-output.log', 'a') as f:
            f.write(f"[{timestamp}] {json.dumps(payload)}\n")

    elif message['type'] == 'error':
        print(f"[{timestamp}] ERROR: {message['description']}")

def main():
    print("="*80)
    print("SIMPLE DASHER MONITOR - DIRECT ATTACH")
    print("="*80)

    # Connect to device
    print("[*] Connecting to USB device...")
    try:
        device = frida.get_usb_device(timeout=5)
        print(f"[+] Connected to: {device.name}")
    except:
        print("[!] Failed to connect to USB device")
        return

    # List all processes to find Dasher
    print("\n[*] Looking for Dasher app...")
    processes = device.enumerate_processes()

    dasher_pid = None
    for proc in processes:
        # Print all potential matches
        if 'dash' in proc.name.lower() or 'door' in proc.name.lower():
            print(f"  Found: {proc.name} (PID: {proc.pid})")
            if 'dasher' in proc.name.lower():
                dasher_pid = proc.pid

    if not dasher_pid:
        print("\n[!] Dasher app not found. Here are ALL running processes with 'app' in name:")
        for proc in processes:
            if 'app' in proc.name.lower():
                print(f"  {proc.name} (PID: {proc.pid})")

        # Manual PID entry
        print("\nEnter the PID of DasherApp manually (or 0 to quit):")
        try:
            dasher_pid = int(input("PID: "))
            if dasher_pid == 0:
                return
        except:
            print("[!] Invalid PID")
            return

    # Attach to the app
    print(f"\n[*] Attaching to PID {dasher_pid}...")
    try:
        session = device.attach(dasher_pid)
        print("[+] Attached successfully!")
    except Exception as e:
        print(f"[!] Failed to attach: {e}")
        return

    # Simple monitoring script
    script_code = """
    console.log("Monitor active - watching for Dash Now tap");

    if (ObjC.available) {
        // Hook NSURLSession to see ALL requests
        try {
            var NSURLSession = ObjC.classes.NSURLSession;

            Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL().absoluteString().toString();
                    var method = request.HTTPMethod() ? request.HTTPMethod().toString() : 'GET';

                    // Log ALL requests
                    send({
                        type: 'REQUEST',
                        method: method,
                        url: url,
                        time: new Date().toISOString()
                    });

                    // Get request body if exists
                    var body = request.HTTPBody();
                    if (body) {
                        try {
                            var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
                            if (bodyStr) {
                                send({
                                    type: 'REQUEST_BODY',
                                    url: url,
                                    body: bodyStr.toString().substring(0, 500)
                                });
                            }
                        } catch(e) {}
                    }

                    // Hook the response
                    var block = new ObjC.Block(args[3]);
                    var origImpl = block.implementation;
                    block.implementation = function(data, resp, error) {
                        if (resp) {
                            var response = new ObjC.Object(resp);
                            var status = response.statusCode();

                            send({
                                type: 'RESPONSE',
                                url: url,
                                status: status.toString(),
                                time: new Date().toISOString()
                            });

                            // Get response body for errors
                            if (status >= 400 && data) {
                                try {
                                    var respStr = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                    if (respStr) {
                                        send({
                                            type: 'ERROR_RESPONSE',
                                            url: url,
                                            status: status.toString(),
                                            body: respStr.toString()
                                        });
                                    }
                                } catch(e) {}
                            }
                        }

                        if (error) {
                            send({
                                type: 'NETWORK_ERROR',
                                url: url,
                                error: error.toString()
                            });
                        }

                        return origImpl(data, resp, error);
                    };
                }
            });

            console.log("Network hooks installed - tap Dash Now when ready");

        } catch(e) {
            console.error("Hook error: " + e);
        }

        // Basic iOS spoof
        try {
            var UIDevice = ObjC.classes.UIDevice;
            Interceptor.attach(UIDevice['- systemVersion'].implementation, {
                onLeave: function(retval) {
                    retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
                }
            });
            console.log("iOS spoofed to 17.6.1");
        } catch(e) {}
    }
    """

    # Create and load script
    print("\n[*] Loading monitoring script...")
    try:
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        print("[+] Script loaded successfully!")
    except Exception as e:
        print(f"[!] Failed to load script: {e}")
        return

    # Wait for input
    print("\n" + "="*80)
    print("MONITORING ACTIVE - TAP 'DASH NOW' IN THE APP")
    print("="*80)
    print("\nThe monitor is now watching all network traffic.")
    print("Please tap 'Dash Now' in the app and wait for the error.")
    print("Press Enter after you see the error to stop monitoring...")
    print("="*80 + "\n")

    try:
        input()  # Wait for user to press Enter
    except KeyboardInterrupt:
        pass

    print("\n[*] Stopping monitor...")
    script.unload()
    session.detach()
    print("[+] Monitor stopped. Check dasher-output.log for details")

if __name__ == "__main__":
    # Clear previous log
    open('dasher-output.log', 'w').close()
    main()