#!/usr/bin/env python3
"""
Autonomous DoorDash API Error Fixer
Monitors, detects, and automatically fixes API errors
"""

import json
import sys
import time
import subprocess
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import frida
import asyncio
import colorama
from colorama import Fore, Style

colorama.init()

class AutonomousFixer:
    def __init__(self):
        self.device = None
        self.session = None
        self.script = None
        self.issues_found = []
        self.fix_applied = False
        
        # Configuration - DASHER APP ONLY
        self.bundle_id = "com.doordash.dasher"  # DASHER app, NOT consumer!
        self.scripts_dir = Path("frida-interception-and-unpinning")
        
        # Script progression (from safest to most comprehensive)
        self.script_progression = [
            ("doordash-minimal-safe.js", "Minimal Safe Mode"),
            ("lightweight-spoof-only.js", "Lightweight Mode"),
            ("comprehensive-spoof-stable.js", "Comprehensive Mode"),
            ("analytics-comprehensive-spoof.js", "Analytics Fix Mode"),
            ("network-capture-enhanced.js", "Enhanced Capture Mode")
        ]
        
    def print_banner(self):
        """Display banner"""
        print("\n" + "="*60)
        print(" "*15 + "AUTONOMOUS API ERROR FIXER")
        print("="*60)
        print(f"{Fore.GREEN}✓ Intelligent Detection{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✓ Automatic Fix Application{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✓ Real-time Analysis{Style.RESET_ALL}")
        print("="*60 + "\n")
    
    def connect_device(self) -> bool:
        """Connect to iPhone via USB"""
        try:
            self.device = frida.get_usb_device()
            print(f"{Fore.GREEN}[✓] Connected to: {self.device.name}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[✗] Connection failed: {e}{Style.RESET_ALL}")
            return False
    
    def check_http_toolkit(self) -> bool:
        """Check if HTTP Toolkit is running"""
        try:
            response = requests.get("http://192.168.50.9:8000", timeout=2)
            return True
        except:
            print(f"{Fore.YELLOW}[!] HTTP Toolkit not detected on port 8000{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    Please start HTTP Toolkit first{Style.RESET_ALL}")
            return False
    
    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message.get('payload', {})
            msg_type = payload.get('type', '')
            
            if msg_type == 'version_inconsistency':
                print(f"\n{Fore.RED}[!] VERSION INCONSISTENCY DETECTED!{Style.RESET_ALL}")
                print(f"    Found: {payload.get('found')}")
                print(f"    Expected: {payload.get('expected')}")
                self.issues_found.append({
                    'type': 'version_inconsistency',
                    'details': payload
                })
                
            elif msg_type == 'api_error':
                print(f"\n{Fore.RED}[!] API ERROR DETECTED!{Style.RESET_ALL}")
                print(f"    URL: {payload.get('url')}")
                print(f"    Status: {payload.get('status')}")
                self.issues_found.append({
                    'type': 'api_error',
                    'details': payload
                })
                
            elif msg_type == 'network_capture':
                stage = payload.get('stage')
                if stage == 'response' and payload.get('statusCode', 200) >= 400:
                    print(f"{Fore.YELLOW}[!] HTTP {payload.get('statusCode')} - {payload.get('url', 'unknown')[:50]}{Style.RESET_ALL}")
                    
            elif msg_type == 'status_report':
                print(f"\r{Fore.CYAN}[*] Captured: {payload.get('requests_captured', 0)} requests, " +
                      f"{payload.get('analytics_events', 0)} analytics events{Style.RESET_ALL}", end='')
    
    def detect_issue_pattern(self) -> str:
        """Analyze issues and determine fix needed"""
        if not self.issues_found:
            return "none"
        
        # Check for version inconsistencies
        version_issues = [i for i in self.issues_found if i['type'] == 'version_inconsistency']
        if version_issues:
            print(f"\n{Fore.YELLOW}[*] Diagnosis: Version inconsistency in analytics{Style.RESET_ALL}")
            return "analytics_fix"
        
        # Check for API errors
        api_errors = [i for i in self.issues_found if i['type'] == 'api_error']
        if api_errors:
            # Check error details
            for error in api_errors:
                body = error['details'].get('body', '')
                if 'ResponseStatusCodeError' in body:
                    print(f"\n{Fore.YELLOW}[*] Diagnosis: API validation error{Style.RESET_ALL}")
                    return "comprehensive_fix"
        
        return "unknown"
    
    def apply_fix(self, fix_type: str) -> bool:
        """Apply the appropriate fix"""
        script_map = {
            'analytics_fix': 'analytics-comprehensive-spoof.js',
            'comprehensive_fix': 'comprehensive-spoof-stable.js',
            'lightweight_fix': 'lightweight-spoof-only.js',
            'minimal_fix': 'doordash-minimal-safe.js'
        }
        
        script_name = script_map.get(fix_type)
        if not script_name:
            return False
        
        script_path = self.scripts_dir / script_name
        
        print(f"\n{Fore.GREEN}[*] Applying fix: {fix_type}{Style.RESET_ALL}")
        print(f"    Script: {script_name}")
        
        # Kill current session if exists
        if self.session:
            self.session.detach()
        
        # Spawn with new script
        try:
            print(f"{Fore.CYAN}[*] Restarting app with fix...{Style.RESET_ALL}")
            pid = self.device.spawn([self.bundle_id])
            self.session = self.device.attach(pid)
            
            # Load fix script
            with open(script_path, 'r') as f:
                script_content = f.read()
            
            self.script = self.session.create_script(script_content)
            self.script.on('message', self.on_message)
            self.script.load()
            
            self.device.resume(pid)
            self.fix_applied = True
            
            print(f"{Fore.GREEN}[✓] Fix applied successfully!{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to apply fix: {e}{Style.RESET_ALL}")
            return False
    
    async def monitor_and_fix(self):
        """Main monitoring and fixing loop"""
        
        # Initial spawn with network capture
        script_path = self.scripts_dir / "network-capture-enhanced.js"
        
        try:
            print(f"{Fore.CYAN}[*] Starting app with network monitoring...{Style.RESET_ALL}")
            pid = self.device.spawn([self.bundle_id])
            self.session = self.device.attach(pid)
            
            with open(script_path, 'r') as f:
                script_content = f.read()
            
            self.script = self.session.create_script(script_content)
            self.script.on('message', self.on_message)
            self.script.load()
            
            self.device.resume(pid)
            
            print(f"{Fore.GREEN}[✓] App started with monitoring{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}[!] Please tap 'Dash Now' button now!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Monitoring for issues...{Style.RESET_ALL}\n")
            
            # Monitor for 30 seconds
            start_time = time.time()
            while time.time() - start_time < 30:
                await asyncio.sleep(1)
                
                # Check if issues detected
                if len(self.issues_found) >= 3:  # Multiple issues found
                    print(f"\n{Fore.YELLOW}[!] Multiple issues detected, analyzing...{Style.RESET_ALL}")
                    break
            
            # Analyze and apply fix
            issue_type = self.detect_issue_pattern()
            
            if issue_type == "none":
                print(f"\n{Fore.GREEN}[✓] No issues detected! App should work normally.{Style.RESET_ALL}")
            elif issue_type == "analytics_fix":
                print(f"\n{Fore.RED}[!] Analytics version inconsistency confirmed{Style.RESET_ALL}")
                if self.apply_fix("analytics_fix"):
                    print(f"\n{Fore.GREEN}[✓] Analytics fix applied!{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Please try 'Dash Now' again{Style.RESET_ALL}")
            elif issue_type == "comprehensive_fix":
                print(f"\n{Fore.RED}[!] API validation errors detected{Style.RESET_ALL}")
                if self.apply_fix("comprehensive_fix"):
                    print(f"\n{Fore.GREEN}[✓] Comprehensive fix applied!{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Please try 'Dash Now' again{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}[?] Unknown issue pattern{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Trying analytics fix as default...{Style.RESET_ALL}")
                self.apply_fix("analytics_fix")
            
            # Continue monitoring after fix
            if self.fix_applied:
                print(f"\n{Fore.CYAN}[*] Monitoring fix effectiveness...{Style.RESET_ALL}")
                await asyncio.sleep(20)
                
                # Check if new issues appeared
                new_issues = len(self.issues_found) - len(self.issues_found)
                if new_issues == 0:
                    print(f"\n{Fore.GREEN}[✓] Fix successful! No new errors detected.{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.YELLOW}[!] Some issues remain, may need manual intervention{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[✗] Error: {e}{Style.RESET_ALL}")
    
    def generate_report(self):
        """Generate final report"""
        print("\n" + "="*60)
        print(" "*20 + "FINAL REPORT")
        print("="*60)
        
        print(f"\nIssues Found: {len(self.issues_found)}")
        
        # Group by type
        version_issues = [i for i in self.issues_found if i['type'] == 'version_inconsistency']
        api_errors = [i for i in self.issues_found if i['type'] == 'api_error']
        
        if version_issues:
            print(f"\n{Fore.RED}Version Inconsistencies: {len(version_issues)}{Style.RESET_ALL}")
            for issue in version_issues[:3]:
                print(f"  - Found {issue['details']['found']} instead of 17.6.1")
        
        if api_errors:
            print(f"\n{Fore.RED}API Errors: {len(api_errors)}{Style.RESET_ALL}")
            for error in api_errors[:3]:
                print(f"  - Status {error['details'].get('status')} at {error['details'].get('url', 'unknown')[:50]}")
        
        if self.fix_applied:
            print(f"\n{Fore.GREEN}[✓] Automatic fix was applied{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No automatic fix needed{Style.RESET_ALL}")
        
        print("\n" + "="*60)
    
    async def run(self):
        """Main execution"""
        self.print_banner()
        
        # Check prerequisites
        if not self.connect_device():
            return
        
        if not self.check_http_toolkit():
            response = input("\nContinue without HTTP Toolkit? (y/n): ")
            if response.lower() != 'y':
                return
        
        # Run monitoring and fixing
        await self.monitor_and_fix()
        
        # Generate report
        self.generate_report()
        
        print(f"\n{Fore.CYAN}[*] Press Enter to exit...{Style.RESET_ALL}")
        input()


if __name__ == "__main__":
    fixer = AutonomousFixer()
    asyncio.run(fixer.run())