#!/usr/bin/env python3
"""
Enhanced Live Frida Monitor for DoorDash Dasher
Captures comprehensive network and error data
"""

import frida
import sys
import time
import json
from datetime import datetime
from colorama import init, Fore, Style

init()

class EnhancedDasherMonitor:
    def __init__(self):
        self.bundle_id = "com.doordash.dasher"
        self.session = None
        self.script = None
        self.monitoring_active = False
        self.captured_data = {
            'requests': [],
            'responses': [],
            'errors': [],
            'analytics': [],
            'console': []
        }

    def on_message(self, message, data):
        """Handle messages from Frida script"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if message['type'] == 'send':
            payload = message['payload']

            # Store all messages
            self.captured_data['console'].append({
                'time': timestamp,
                'payload': payload
            })

            # Parse structured messages
            if isinstance(payload, dict):
                msg_type = payload.get('type', 'UNKNOWN')

                if msg_type == 'REQUEST':
                    print(f"{Fore.CYAN}[{timestamp}] → REQUEST: {payload.get('method')} {payload.get('url')}{Style.RESET_ALL}")
                    self.captured_data['requests'].append(payload)

                elif msg_type == 'RESPONSE':
                    status = payload.get('statusCode', '?')
                    url = payload.get('url', 'unknown')
                    color = Fore.RED if int(status) >= 400 else Fore.GREEN
                    print(f"{color}[{timestamp}] ← RESPONSE: {status} from {url}{Style.RESET_ALL}")
                    self.captured_data['responses'].append(payload)

                elif msg_type == 'ERROR':
                    print(f"{Fore.RED}[{timestamp}] ⚠ ERROR: {payload.get('message')}{Style.RESET_ALL}")
                    self.captured_data['errors'].append(payload)

                elif msg_type == 'ANALYTICS':
                    print(f"{Fore.YELLOW}[{timestamp}] 📊 ANALYTICS: {payload.get('event')}{Style.RESET_ALL}")
                    self.captured_data['analytics'].append(payload)

                elif msg_type == 'BODY':
                    # Only print first 200 chars of body
                    body_preview = str(payload.get('body', ''))[:200]
                    print(f"{Fore.MAGENTA}[{timestamp}] BODY: {body_preview}...{Style.RESET_ALL}")

            else:
                # Regular console messages
                if 'error' in str(payload).lower():
                    print(f"{Fore.RED}[{timestamp}] {payload}{Style.RESET_ALL}")
                elif 'dash' in str(payload).lower():
                    print(f"{Fore.YELLOW}[{timestamp}] {payload}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.WHITE}[{timestamp}] {payload}{Style.RESET_ALL}")

        elif message['type'] == 'error':
            print(f"{Fore.RED}[{timestamp}] SCRIPT ERROR: {message['description']}{Style.RESET_ALL}")
            self.captured_data['errors'].append({
                'time': timestamp,
                'type': 'SCRIPT_ERROR',
                'message': message['description']
            })

    def start_monitoring(self):
        """Start monitoring the Dasher app"""
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}ENHANCED DASHER MONITOR - INITIALIZING{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")

        # Connect to device
        print(f"{Fore.GREEN}[*] Connecting to USB device...{Style.RESET_ALL}")
        try:
            device = frida.get_usb_device(timeout=10)
            print(f"{Fore.GREEN}[+] Connected to: {device.name}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to connect: {e}{Style.RESET_ALL}")
            return False

        # Find and attach to Dasher app
        print(f"{Fore.GREEN}[*] Looking for DoorDash Dasher app...{Style.RESET_ALL}")
        try:
            processes = device.enumerate_processes()
            dasher_pid = None

            # Look for various possible names
            for proc in processes:
                if any(x in proc.name.lower() for x in ['dasher', 'doordash.dasher', self.bundle_id]):
                    dasher_pid = proc.pid
                    print(f"{Fore.GREEN}[+] Found: {proc.name} (PID: {proc.pid}){Style.RESET_ALL}")
                    break

            if not dasher_pid:
                print(f"{Fore.RED}[!] Dasher app not found! Please start it first.{Style.RESET_ALL}")
                print("Running processes:")
                for proc in processes:
                    if 'dash' in proc.name.lower():
                        print(f"  - {proc.name} (PID: {proc.pid})")
                return False

            self.session = device.attach(dasher_pid)
            print(f"{Fore.GREEN}[+] Attached successfully!{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to attach: {e}{Style.RESET_ALL}")
            return False

        # Enhanced monitoring script
        monitoring_script = """
        console.log("[MONITOR] Enhanced monitoring active!");

        if (ObjC.available) {
            // ============= NETWORK MONITORING =============
            try {
                var NSURLSession = ObjC.classes.NSURLSession;
                var NSURLRequest = ObjC.classes.NSMutableURLRequest;

                // Monitor ALL network requests
                Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
                    onEnter: function(args) {
                        var request = new ObjC.Object(args[2]);
                        var url = request.URL().absoluteString().toString();
                        var method = request.HTTPMethod() ? request.HTTPMethod().toString() : 'GET';
                        var headers = {};

                        // Get headers
                        var headerDict = request.allHTTPHeaderFields();
                        if (headerDict) {
                            var keys = headerDict.allKeys();
                            for (var i = 0; i < keys.count(); i++) {
                                var key = keys.objectAtIndex_(i).toString();
                                headers[key] = headerDict.objectForKey_(key).toString();
                            }
                        }

                        send({
                            type: 'REQUEST',
                            url: url,
                            method: method,
                            headers: headers,
                            timestamp: Date.now()
                        });

                        // Capture request body
                        var httpBody = request.HTTPBody();
                        if (httpBody) {
                            try {
                                var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(httpBody, 4);
                                if (bodyStr) {
                                    send({
                                        type: 'BODY',
                                        direction: 'REQUEST',
                                        url: url,
                                        body: bodyStr.toString()
                                    });
                                }
                            } catch(e) {}
                        }

                        // Hook the completion handler to catch responses
                        var completionBlock = new ObjC.Block(args[3]);
                        var originalImpl = completionBlock.implementation;

                        completionBlock.implementation = function(data, response, error) {
                            if (response) {
                                var httpResponse = new ObjC.Object(response);
                                var statusCode = httpResponse.statusCode();

                                send({
                                    type: 'RESPONSE',
                                    url: url,
                                    statusCode: statusCode.toString(),
                                    timestamp: Date.now()
                                });

                                // Capture response body, especially for errors
                                if (data && statusCode >= 400) {
                                    try {
                                        var responseStr = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                        if (responseStr) {
                                            send({
                                                type: 'ERROR',
                                                url: url,
                                                statusCode: statusCode.toString(),
                                                message: responseStr.toString()
                                            });
                                        }
                                    } catch(e) {}
                                }
                            }

                            if (error) {
                                send({
                                    type: 'ERROR',
                                    url: url,
                                    message: error.localizedDescription().toString()
                                });
                            }

                            return originalImpl(data, response, error);
                        };
                    }
                });

                console.log("[MONITOR] Network hooks installed!");

            } catch(e) {
                console.error("[MONITOR] Network hook error: " + e);
            }

            // ============= ANALYTICS MONITORING =============
            try {
                // Monitor JSON serialization for analytics
                var NSJSONSerialization = ObjC.classes.NSJSONSerialization;

                Interceptor.attach(NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
                    onEnter: function(args) {
                        var obj = new ObjC.Object(args[2]);
                        var str = obj.toString();

                        // Look for analytics-related payloads
                        if (str.includes('event') || str.includes('analytics') ||
                            str.includes('device_os_version') || str.includes('dash')) {

                            // Try to extract key info
                            if (obj.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                var eventName = obj.objectForKey_('event');
                                var osVersion = obj.objectForKey_('device_os_version');

                                send({
                                    type: 'ANALYTICS',
                                    event: eventName ? eventName.toString() : 'unknown',
                                    os_version: osVersion ? osVersion.toString() : 'not set',
                                    preview: str.substring(0, 200)
                                });
                            }
                        }
                    }
                });

                console.log("[MONITOR] Analytics hooks installed!");

            } catch(e) {
                console.error("[MONITOR] Analytics hook error: " + e);
            }

            // ============= ERROR DETECTION =============
            try {
                // Hook NSError creation
                var NSError = ObjC.classes.NSError;

                Interceptor.attach(NSError['+ errorWithDomain:code:userInfo:'].implementation, {
                    onEnter: function(args) {
                        var domain = new ObjC.Object(args[2]).toString();
                        var code = args[3].toInt32();

                        if (domain.includes('ErrorNetworking') || domain.includes('DoorDash')) {
                            send({
                                type: 'ERROR',
                                domain: domain,
                                code: code,
                                message: 'NSError created'
                            });
                        }
                    }
                });

                console.log("[MONITOR] Error detection installed!");

            } catch(e) {
                console.error("[MONITOR] Error hook error: " + e);
            }

            // ============= MINIMAL SPOOFING =============
            try {
                // Just basic iOS version spoofing to prevent detection
                var UIDevice = ObjC.classes.UIDevice;
                Interceptor.attach(UIDevice['- systemVersion'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ObjC.classes.NSString.stringWithString_("17.6.1"));
                    }
                });

                console.log("[MONITOR] iOS 17.6.1 spoof active (minimal)");

            } catch(e) {
                console.error("[MONITOR] Spoof error: " + e);
            }
        }

        console.log("[MONITOR] All hooks installed - Ready to capture!");
        """

        try:
            self.script = self.session.create_script(monitoring_script)
            self.script.on('message', self.on_message)
            self.script.load()
            print(f"{Fore.GREEN}[+] Enhanced monitoring script loaded!{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load script: {e}{Style.RESET_ALL}")
            return False

        self.monitoring_active = True
        return True

    def wait_for_dash_now(self):
        """Interactive monitoring session"""
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}MONITORING ACTIVE - TAP 'DASH NOW' WHEN READY{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Commands:{Style.RESET_ALL}")
        print(f"  - Type 'tapped' after you tap Dash Now")
        print(f"  - Type 'error' after you see the error")
        print(f"  - Type 'done' to finish and save")
        print(f"  - Type 'quit' to exit")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")

        tap_time = None
        error_time = None

        try:
            while self.monitoring_active:
                user_input = input().strip().lower()

                if user_input == 'tapped':
                    tap_time = datetime.now()
                    print(f"{Fore.CYAN}[MARKED] Dash Now tapped at {tap_time.strftime('%H:%M:%S')}{Style.RESET_ALL}")

                elif user_input == 'error':
                    error_time = datetime.now()
                    print(f"{Fore.RED}[MARKED] Error appeared at {error_time.strftime('%H:%M:%S')}{Style.RESET_ALL}")

                elif user_input == 'done':
                    self.save_analysis(tap_time, error_time)
                    break

                elif user_input == 'quit':
                    print(f"{Fore.YELLOW}[*] Stopping monitor...{Style.RESET_ALL}")
                    break

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Monitor interrupted{Style.RESET_ALL}")

        self.monitoring_active = False

    def save_analysis(self, tap_time, error_time):
        """Save and analyze captured data"""
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}ANALYSIS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")

        # Summary stats
        print(f"\n{Fore.GREEN}Captured Data:{Style.RESET_ALL}")
        print(f"  • Requests: {len(self.captured_data['requests'])}")
        print(f"  • Responses: {len(self.captured_data['responses'])}")
        print(f"  • Errors: {len(self.captured_data['errors'])}")
        print(f"  • Analytics Events: {len(self.captured_data['analytics'])}")

        # Show errors
        if self.captured_data['errors']:
            print(f"\n{Fore.RED}Errors Detected:{Style.RESET_ALL}")
            for error in self.captured_data['errors'][-5:]:
                print(f"  • {error}")

        # Show failed requests
        failed_responses = [r for r in self.captured_data['responses'] if int(r.get('statusCode', 0)) >= 400]
        if failed_responses:
            print(f"\n{Fore.RED}Failed Requests:{Style.RESET_ALL}")
            for resp in failed_responses[-5:]:
                print(f"  • {resp.get('statusCode')} - {resp.get('url')}")

        # Save full log
        filename = f"dasher-monitor-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump({
                'tap_time': tap_time.isoformat() if tap_time else None,
                'error_time': error_time.isoformat() if error_time else None,
                'data': self.captured_data,
                'summary': {
                    'total_requests': len(self.captured_data['requests']),
                    'failed_requests': len(failed_responses),
                    'errors': len(self.captured_data['errors'])
                }
            }, f, indent=2)

        print(f"\n{Fore.GREEN}[+] Full log saved to {filename}{Style.RESET_ALL}")

    def cleanup(self):
        """Clean up resources"""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()
        print(f"{Fore.GREEN}[+] Monitor cleaned up{Style.RESET_ALL}")

def main():
    monitor = EnhancedDasherMonitor()

    try:
        if monitor.start_monitoring():
            monitor.wait_for_dash_now()
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    main()