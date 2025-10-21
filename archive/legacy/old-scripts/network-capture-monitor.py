#!/usr/bin/env python3
"""
Autonomous Network Capture Monitor for DoorDash Frida Interception
Captures, analyzes, and fixes API errors in real-time
"""

import json
import re
import sys
import time
import asyncio
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import frida

class NetworkCaptureMonitor:
    def __init__(self):
        self.captured_requests = []
        self.captured_responses = []
        self.version_inconsistencies = []
        self.api_errors = []
        self.monitoring = True
        self.device = None
        self.session = None
        self.script = None
        
        # Patterns to detect
        self.error_patterns = [
            r"ErrorNetworking\.ResponseStatusCodeError",
            r"error\s+1\)",
            r"unable to start your dash",
            r"operation couldn't be completed"
        ]
        
        # Version patterns
        self.ios_version_pattern = r'"(?:device_)?os_version"\s*:\s*"([^"]+)"'
        self.expected_version = "17.6.1"
        self.actual_version = "16.3.1"
        
    def connect_device(self):
        """Connect to USB device via Frida"""
        try:
            self.device = frida.get_usb_device()
            print(f"[✓] Connected to device: {self.device.name}")
            return True
        except Exception as e:
            print(f"[✗] Failed to connect: {e}")
            return False
    
    def analyze_traffic(self, data: Dict[str, Any]):
        """Analyze captured network traffic for issues"""
        
        # Check for API errors
        if "response" in data:
            response_body = str(data.get("response", {}).get("body", ""))
            status_code = data.get("response", {}).get("status", 200)
            
            # Check for error patterns
            for pattern in self.error_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    self.api_errors.append({
                        "timestamp": datetime.now().isoformat(),
                        "url": data.get("url", ""),
                        "status": status_code,
                        "error": pattern,
                        "body_snippet": response_body[:500]
                    })
                    print(f"\n[!] API ERROR DETECTED: {pattern}")
                    print(f"    URL: {data.get('url', '')}")
                    print(f"    Status: {status_code}")
                    self.suggest_fix(data)
        
        # Check for version inconsistency
        if "request" in data:
            request_body = str(data.get("request", {}).get("body", ""))
            
            # Find all iOS version mentions
            versions = re.findall(self.ios_version_pattern, request_body)
            for version in versions:
                if version != self.expected_version:
                    self.version_inconsistencies.append({
                        "timestamp": datetime.now().isoformat(),
                        "url": data.get("url", ""),
                        "found_version": version,
                        "expected_version": self.expected_version,
                        "context": request_body[:200]
                    })
                    print(f"\n[!] VERSION INCONSISTENCY DETECTED!")
                    print(f"    Found: {version} (should be {self.expected_version})")
                    print(f"    URL: {data.get('url', '')}")
    
    def suggest_fix(self, data: Dict[str, Any]):
        """Suggest fixes based on detected issues"""
        
        print("\n[*] SUGGESTED FIXES:")
        
        # Check if it's a version-related error
        if self.version_inconsistencies:
            print("    1. Version inconsistency detected - switching to Analytics Mode")
            print("    2. The app is reporting mixed iOS versions")
            print("    3. Recommendation: Use option [7] or [8] for Analytics Fix")
            
            # Auto-suggest command
            print("\n[*] AUTO-FIX COMMAND:")
            print("    python frida-spawn.py doordash.DoorDashConsumer frida-interception-and-unpinning\\analytics-comprehensive-spoof.js")
        
        # Check if it's an attestation error
        if "attest" in str(data).lower():
            print("    - App Attestation detected - may need additional bypass")
            print("    - Consider using jailbreak detection bypass")
    
    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message.get('payload', {})
            
            # Process network capture
            if payload.get('type') == 'network_capture':
                self.captured_requests.append(payload)
                self.analyze_traffic(payload)
                
                # Save to file for analysis
                self.save_capture(payload)
        
        elif message['type'] == 'error':
            print(f"[✗] Script error: {message['stack']}")
    
    def save_capture(self, data: Dict[str, Any]):
        """Save captured data to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"captures/network_capture_{timestamp}.json"
        
        Path("captures").mkdir(exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def generate_report(self):
        """Generate analysis report"""
        print("\n" + "="*60)
        print("NETWORK CAPTURE ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nTotal Requests Captured: {len(self.captured_requests)}")
        print(f"API Errors Detected: {len(self.api_errors)}")
        print(f"Version Inconsistencies: {len(self.version_inconsistencies)}")
        
        if self.version_inconsistencies:
            print("\n[!] VERSION INCONSISTENCY SUMMARY:")
            for issue in self.version_inconsistencies[:5]:  # Show first 5
                print(f"    - {issue['found_version']} found (expected {issue['expected_version']})")
                print(f"      URL: {issue['url']}")
        
        if self.api_errors:
            print("\n[!] API ERROR SUMMARY:")
            for error in self.api_errors[:5]:  # Show first 5
                print(f"    - Status {error['status']}: {error['error']}")
                print(f"      URL: {error['url']}")
        
        # Final recommendation
        print("\n[*] FINAL RECOMMENDATION:")
        if self.version_inconsistencies:
            print("    ✅ Use Analytics Fix Mode (option 7 or 8)")
            print("    ✅ This will ensure 100% version consistency")
        elif self.api_errors and not self.version_inconsistencies:
            print("    ⚠️  API errors without version issues - may be rate limiting")
            print("    ⚠️  Try waiting 30 seconds and retry")
        else:
            print("    ✓ No major issues detected")
    
    async def monitor_realtime(self):
        """Monitor in real-time until user triggers action"""
        print("\n[*] Real-time monitoring started...")
        print("[*] Please open DoorDash app now")
        print("[*] I'll tell you when to tap 'Dash Now'")
        
        # Wait for app to stabilize
        await asyncio.sleep(5)
        
        print("\n[!] READY: Please tap 'Dash Now' button now!")
        print("[*] Monitoring network traffic...")
        
        # Monitor for 30 seconds after tap
        start_time = time.time()
        while time.time() - start_time < 30:
            await asyncio.sleep(1)
            
            # Check for errors in real-time
            if self.api_errors or self.version_inconsistencies:
                print(f"\n[!] Issues detected after {int(time.time() - start_time)} seconds")
                break
        
        print("\n[*] Capture complete. Analyzing...")
        self.generate_report()
    
    def start_capture(self, bundle_id="com.doordash.dasher", script_path=None):
        """Start network capture with enhanced script"""
        
        if not self.connect_device():
            return False
        
        # Use analytics script by default
        if not script_path:
            script_path = "frida-interception-and-unpinning/analytics-comprehensive-spoof.js"
        
        # Load and enhance script with network capture
        with open(script_path, 'r') as f:
            base_script = f.read()
        
        # Add network capture enhancement
        network_capture_code = """
        // Network Capture Enhancement
        if (ObjC.available) {
            // Hook NSURLSession for network capture
            var NSURLSession = ObjC.classes.NSURLSession;
            
            Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL().absoluteString().toString();
                    var method = request.HTTPMethod().toString();
                    var headers = request.allHTTPHeaderFields();
                    var body = request.HTTPBody();
                    
                    var bodyString = "";
                    if (body && !body.isNull()) {
                        bodyString = NSString.alloc().initWithData_encoding_(body, 4).toString();
                    }
                    
                    send({
                        type: 'network_capture',
                        timestamp: Date.now(),
                        url: url,
                        method: method,
                        request: {
                            headers: headers ? headers.toString() : {},
                            body: bodyString
                        }
                    });
                }
            });
        }
        """
        
        # Combine scripts
        full_script = base_script + "\n\n" + network_capture_code
        
        try:
            # Spawn or attach to app
            print(f"[*] Spawning {bundle_id} with enhanced capture...")
            pid = self.device.spawn([bundle_id])
            self.session = self.device.attach(pid)
            
            # Create and load script
            self.script = self.session.create_script(full_script)
            self.script.on('message', self.on_message)
            self.script.load()
            
            # Resume app
            self.device.resume(pid)
            
            print(f"[✓] App started with network capture enabled")
            return True
            
        except Exception as e:
            print(f"[✗] Failed to start capture: {e}")
            return False


async def main():
    """Main execution"""
    monitor = NetworkCaptureMonitor()
    
    print("="*60)
    print("AUTONOMOUS NETWORK CAPTURE & FIX SYSTEM")
    print("="*60)
    
    # Start capture
    if monitor.start_capture():
        # Run real-time monitoring
        await monitor.monitor_realtime()
    else:
        print("[✗] Failed to start monitoring")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())