#!/usr/bin/env python3
"""
Live Network Monitor - Advanced Frida script for real-time network manipulation

This script provides live monitoring and manipulation capabilities for iOS apps.
You can intercept, log, modify, and replay network requests in real-time.

Usage:
    python live-network-monitor.py <bundle_id> [--attach PID] [--log-file FILE]

Examples:
    # Spawn mode (restart app)
    python live-network-monitor.py com.doordash.dasher

    # Attach mode (keep session)
    python live-network-monitor.py com.doordash.dasher --attach 1234

    # With custom log file
    python live-network-monitor.py com.doordash.dasher --log-file dasher-traffic.log
"""

import frida
import sys
import os
import json
import time
import argparse
from datetime import datetime
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

class NetworkMonitor:
    def __init__(self, bundle_id, attach_pid=None, log_file=None):
        self.bundle_id = bundle_id
        self.attach_pid = attach_pid
        self.log_file = log_file or f"logs/{bundle_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
        self.session = None
        self.script = None

        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)

        # Statistics
        self.stats = {
            "requests": 0,
            "responses": 0,
            "ssl_bypasses": 0,
            "proxy_configs": 0
        }

    def log(self, message, level="INFO"):
        """Log message to console and file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"

        # Console output with colors
        if level == "ERROR":
            print(Fore.RED + log_entry)
        elif level == "SUCCESS":
            print(Fore.GREEN + log_entry)
        elif level == "WARNING":
            print(Fore.YELLOW + log_entry)
        elif level == "REQUEST":
            print(Fore.CYAN + log_entry)
        elif level == "RESPONSE":
            print(Fore.MAGENTA + log_entry)
        else:
            print(log_entry)

        # File output
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")

    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message['payload']

            # Handle different message types
            if isinstance(payload, dict):
                msg_type = payload.get('type', 'unknown')

                if msg_type == 'request':
                    self.stats['requests'] += 1
                    self.log(f"REQUEST: {payload.get('method')} {payload.get('url')}", "REQUEST")
                    if payload.get('headers'):
                        self.log(f"  Headers: {json.dumps(payload['headers'], indent=2)}", "REQUEST")
                    if payload.get('body'):
                        self.log(f"  Body: {payload['body'][:200]}...", "REQUEST")

                elif msg_type == 'response':
                    self.stats['responses'] += 1
                    self.log(f"RESPONSE: {payload.get('status')} {payload.get('url')}", "RESPONSE")
                    if payload.get('headers'):
                        self.log(f"  Headers: {json.dumps(payload['headers'], indent=2)}", "RESPONSE")
                    if payload.get('body'):
                        self.log(f"  Body: {payload['body'][:200]}...", "RESPONSE")

                elif msg_type == 'ssl_bypass':
                    self.stats['ssl_bypasses'] += 1
                    self.log(f"SSL BYPASS: {payload.get('message')}", "SUCCESS")

                elif msg_type == 'proxy_config':
                    self.stats['proxy_configs'] += 1
                    self.log(f"PROXY CONFIG: {payload.get('message')}", "SUCCESS")

                else:
                    self.log(f"{payload}", "INFO")
            else:
                self.log(f"{payload}", "INFO")

        elif message['type'] == 'error':
            self.log(f"Error: {message.get('stack', message)}", "ERROR")

    def load_script(self):
        """Load the monitoring Frida script"""
        script_path = "frida-interception-and-unpinning/enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js"

        if not os.path.exists(script_path):
            self.log(f"Script not found: {script_path}", "ERROR")
            sys.exit(1)

        with open(script_path, 'r') as f:
            script_code = f.read()

        # Add advanced monitoring hooks
        advanced_hooks = """
// Advanced Network Monitoring Hooks
console.log("[*] Loading advanced monitoring hooks...");

// Hook NSURLConnection for detailed request/response logging
if (ObjC.available && ObjC.classes.NSURLConnection) {
    var NSURLConnection = ObjC.classes.NSURLConnection;

    // Hook sendSynchronousRequest
    try {
        var sendSync = NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'];
        if (sendSync) {
            Interceptor.attach(sendSync.implementation, {
                onEnter: function(args) {
                    try {
                        var request = new ObjC.Object(args[2]);
                        var url = request.URL().absoluteString().toString();
                        var method = request.HTTPMethod().toString();

                        send({
                            type: 'request',
                            method: method,
                            url: url,
                            timestamp: new Date().toISOString()
                        });
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}
}

// Hook NSURLSessionTask for task-level tracking
if (ObjC.available && ObjC.classes.NSURLSessionTask) {
    try {
        var NSURLSessionTask = ObjC.classes.NSURLSessionTask;
        var resume = NSURLSessionTask['- resume'];

        if (resume) {
            Interceptor.attach(resume.implementation, {
                onEnter: function(args) {
                    try {
                        var task = new ObjC.Object(args[0]);
                        var request = task.currentRequest();
                        if (request) {
                            var url = request.URL().absoluteString().toString();
                            var method = request.HTTPMethod().toString();

                            send({
                                type: 'request',
                                method: method,
                                url: url,
                                timestamp: new Date().toISOString()
                            });
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}
}

console.log("[+] Advanced monitoring hooks loaded");
"""

        script_code += advanced_hooks
        return script_code

    def start(self):
        """Start the monitoring session"""
        try:
            # Connect to USB device
            device = frida.get_usb_device()
            self.log(f"Connected to device: {device.name}", "SUCCESS")

            # Attach or spawn
            if self.attach_pid:
                self.log(f"Attaching to PID {self.attach_pid}...", "INFO")
                self.session = device.attach(self.attach_pid)
            else:
                self.log(f"Spawning {self.bundle_id}...", "INFO")
                pid = device.spawn([self.bundle_id])
                self.session = device.attach(pid)

            # Load script
            self.log("Loading monitoring script...", "INFO")
            script_code = self.load_script()
            self.script = self.session.create_script(script_code)
            self.script.on('message', self.on_message)
            self.script.load()

            # Resume if spawned
            if not self.attach_pid:
                device.resume(device.get_process(self.bundle_id).pid)

            self.log("Monitoring started! Press Ctrl+C to stop.", "SUCCESS")
            self.log(f"Logging to: {self.log_file}", "INFO")
            self.log("=" * 80, "INFO")

            # Keep running
            try:
                sys.stdin.read()
            except KeyboardInterrupt:
                self.log("\nStopping monitor...", "INFO")
                self.print_stats()
                self.session.detach()

        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            sys.exit(1)

    def print_stats(self):
        """Print monitoring statistics"""
        self.log("=" * 80, "INFO")
        self.log("MONITORING STATISTICS", "INFO")
        self.log("=" * 80, "INFO")
        self.log(f"Total Requests: {self.stats['requests']}", "INFO")
        self.log(f"Total Responses: {self.stats['responses']}", "INFO")
        self.log(f"SSL Bypasses: {self.stats['ssl_bypasses']}", "INFO")
        self.log(f"Proxy Configurations: {self.stats['proxy_configs']}", "INFO")
        self.log("=" * 80, "INFO")

def main():
    parser = argparse.ArgumentParser(
        description='Live Network Monitor for iOS apps via Frida',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('bundle_id', help='iOS app bundle identifier (e.g., com.doordash.dasher)')
    parser.add_argument('--attach', type=int, metavar='PID', help='Attach to running process PID instead of spawning')
    parser.add_argument('--log-file', metavar='FILE', help='Custom log file path')

    args = parser.parse_args()

    monitor = NetworkMonitor(
        bundle_id=args.bundle_id,
        attach_pid=args.attach,
        log_file=args.log_file
    )

    monitor.start()

if __name__ == "__main__":
    main()
