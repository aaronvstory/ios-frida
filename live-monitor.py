#!/usr/bin/env python3
"""
Live Frida Monitor for DoorDash Dasher
Captures and displays real-time output when user taps "Dash Now"
"""

import frida
import sys
import time
import json
from datetime import datetime
from colorama import init, Fore, Style

init()

class LiveDasherMonitor:
    def __init__(self):
        self.bundle_id = "com.doordash.dasher"  # DASHER APP ONLY!
        self.session = None
        self.script = None
        self.monitoring_active = False
        self.captured_requests = []
        self.captured_errors = []

    def on_message(self, message, data):
        """Handle messages from Frida script"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if message['type'] == 'send':
            payload = message['payload']

            # Color-code different message types
            if 'error' in str(payload).lower():
                print(f"{Fore.RED}[{timestamp}] ERROR: {payload}{Style.RESET_ALL}")
                self.captured_errors.append({
                    'time': timestamp,
                    'message': payload
                })
            elif 'request' in str(payload).lower() or 'api' in str(payload).lower():
                print(f"{Fore.CYAN}[{timestamp}] API: {payload}{Style.RESET_ALL}")
                self.captured_requests.append({
                    'time': timestamp,
                    'message': payload
                })
            elif 'dash' in str(payload).lower():
                print(f"{Fore.YELLOW}[{timestamp}] DASH: {payload}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[{timestamp}] {payload}{Style.RESET_ALL}")

        elif message['type'] == 'error':
            print(f"{Fore.RED}[{timestamp}] SCRIPT ERROR: {message['description']}{Style.RESET_ALL}")

    def start_monitoring(self):
        """Start monitoring the Dasher app"""
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}LIVE DASHER MONITOR - READY TO CAPTURE{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")

        # Connect to device
        print(f"{Fore.GREEN}[*] Connecting to USB device...{Style.RESET_ALL}")
        try:
            device = frida.get_usb_device(timeout=10)
            print(f"{Fore.GREEN}[+] Connected to: {device.name}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to connect: {e}{Style.RESET_ALL}")
            return False

        # Attach to Dasher app
        print(f"{Fore.GREEN}[*] Attaching to DoorDash Dasher...{Style.RESET_ALL}")
        try:
            # Find the Dasher app PID
            processes = device.enumerate_processes()
            dasher_pid = None
            for proc in processes:
                if self.bundle_id in proc.name or 'dasher' in proc.name.lower():
                    dasher_pid = proc.pid
                    print(f"{Fore.GREEN}[+] Found Dasher app: {proc.name} (PID: {proc.pid}){Style.RESET_ALL}")
                    break

            if not dasher_pid:
                print(f"{Fore.RED}[!] Dasher app not running! Please start it first.{Style.RESET_ALL}")
                return False

            self.session = device.attach(dasher_pid)
            print(f"{Fore.GREEN}[+] Attached successfully!{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to attach: {e}{Style.RESET_ALL}")
            return False

        # Load monitoring script
        monitoring_script = """
        console.log("[MONITOR] Live monitoring script loaded!");

        // Hook NSURLSession for all network requests
        if (ObjC.available) {
            try {
                var NSURLSession = ObjC.classes.NSURLSession;

                // Hook dataTaskWithRequest
                Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
                    onEnter: function(args) {
                        var request = new ObjC.Object(args[2]);
                        var url = request.URL().absoluteString();
                        var method = request.HTTPMethod();

                        // Focus on dash-related endpoints
                        if (url.toString().toLowerCase().includes('dash') ||
                            url.toString().toLowerCase().includes('shift') ||
                            url.toString().toLowerCase().includes('schedule')) {

                            send({
                                type: 'REQUEST',
                                url: url.toString(),
                                method: method ? method.toString() : 'GET',
                                headers: request.allHTTPHeaderFields() ? request.allHTTPHeaderFields().toString() : '{}'
                            });

                            // Try to capture body if it exists
                            var httpBody = request.HTTPBody();
                            if (httpBody) {
                                var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(httpBody, 4);
                                send({
                                    type: 'REQUEST_BODY',
                                    body: bodyStr ? bodyStr.toString() : 'binary data'
                                });
                            }
                        }
                    }
                });

                // Hook the response handler
                var origMethod = NSURLSession['- dataTaskWithRequest:completionHandler:'];
                if (origMethod) {
                    Interceptor.attach(origMethod.implementation, {
                        onEnter: function(args) {
                            var completionHandler = new ObjC.Block(args[3]);
                            var origImpl = completionHandler.implementation;

                            completionHandler.implementation = function(data, response, error) {
                                if (response) {
                                    var httpResponse = new ObjC.Object(response);
                                    var statusCode = httpResponse.statusCode();
                                    var url = httpResponse.URL().absoluteString();

                                    // Check for errors
                                    if (statusCode >= 400) {
                                        send({
                                            type: 'ERROR_RESPONSE',
                                            url: url.toString(),
                                            statusCode: statusCode.toString(),
                                            error: error ? error.toString() : 'No error object'
                                        });

                                        // Try to get response body
                                        if (data) {
                                            var responseStr = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                            send({
                                                type: 'ERROR_BODY',
                                                body: responseStr ? responseStr.toString() : 'binary data'
                                            });
                                        }
                                    }
                                }

                                // Call original handler
                                origImpl(data, response, error);
                            };
                        }
                    });
                }

                console.log("[MONITOR] Network hooks installed!");

            } catch(e) {
                console.error("[MONITOR] Error setting up hooks: " + e);
            }

            // Also monitor for any ErrorNetworking strings
            var modules = Process.enumerateModules();
            modules.forEach(function(module) {
                if (module.name.toLowerCase().includes('dasher') ||
                    module.name.toLowerCase().includes('doordash')) {

                    Memory.scan(module.base, module.size, 'ErrorNetworking', {
                        onMatch: function(address, size) {
                            console.log('[MONITOR] Found ErrorNetworking string at: ' + address);
                        },
                        onComplete: function() {
                            console.log('[MONITOR] Scan complete');
                        }
                    });
                }
            });
        }

        // Minimal safe spoofing to keep app stable
        if (ObjC.available) {
            var UIDevice = ObjC.classes.UIDevice;
            Interceptor.attach(UIDevice['- systemVersion'].implementation, {
                onLeave: function(retval) {
                    retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
                }
            });
            console.log("[MONITOR] Basic iOS spoof active: 17.6.1");
        }
        """

        try:
            self.script = self.session.create_script(monitoring_script)
            self.script.on('message', self.on_message)
            self.script.load()
            print(f"{Fore.GREEN}[+] Monitoring script loaded!{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load script: {e}{Style.RESET_ALL}")
            return False

        self.monitoring_active = True
        return True

    def wait_for_dash_now(self):
        """Wait for user to tap Dash Now and monitor the output"""
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}MONITORING ACTIVE - READY FOR 'DASH NOW' TAP{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Please tap 'Dash Now' in the app when ready...{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Type 'done' after you see the error, or 'quit' to exit{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")

        try:
            while self.monitoring_active:
                user_input = input().strip().lower()

                if user_input == 'done':
                    print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}ANALYSIS SUMMARY{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")

                    print(f"\n{Fore.YELLOW}Captured Errors ({len(self.captured_errors)}):{Style.RESET_ALL}")
                    for error in self.captured_errors:
                        print(f"  {error['time']}: {error['message']}")

                    print(f"\n{Fore.YELLOW}Captured Requests ({len(self.captured_requests)}):{Style.RESET_ALL}")
                    for req in self.captured_requests[-10:]:  # Last 10 requests
                        print(f"  {req['time']}: {req['message']}")

                    # Save to file
                    with open('dasher-monitor-log.json', 'w') as f:
                        json.dump({
                            'errors': self.captured_errors,
                            'requests': self.captured_requests,
                            'timestamp': datetime.now().isoformat()
                        }, f, indent=2)
                    print(f"\n{Fore.GREEN}[+] Log saved to dasher-monitor-log.json{Style.RESET_ALL}")
                    break

                elif user_input == 'quit':
                    print(f"{Fore.YELLOW}[*] Stopping monitor...{Style.RESET_ALL}")
                    break

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Monitor interrupted{Style.RESET_ALL}")

        self.monitoring_active = False

    def cleanup(self):
        """Clean up resources"""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()
        print(f"{Fore.GREEN}[+] Monitor cleaned up{Style.RESET_ALL}")

def main():
    monitor = LiveDasherMonitor()

    try:
        if monitor.start_monitoring():
            monitor.wait_for_dash_now()
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    main()