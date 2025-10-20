#!/usr/bin/env python3
"""
Direct Analytics Fix for DoorDash DASHER
Simply applies the analytics comprehensive spoof
"""

import frida
import sys
import time
from pathlib import Path

def on_message(message, data):
    """Handle messages from Frida script"""
    if message['type'] == 'send':
        payload = message.get('payload', '')
        print(f"[*] {payload}")
    elif message['type'] == 'error':
        print(f"[!] {message['stack']}")

def main():
    print("="*60)
    print(" "*10 + "DIRECT ANALYTICS FIX FOR DASHER")
    print("="*60)
    
    bundle_id = "com.doordash.dasher"
    script_path = Path("frida-interception-and-unpinning/analytics-comprehensive-spoof.js")
    
    # Connect to device
    try:
        device = frida.get_usb_device()
        print(f"[✓] Connected to: {device.name}")
    except Exception as e:
        print(f"[✗] Failed to connect: {e}")
        sys.exit(1)
    
    # Load script
    if not script_path.exists():
        print(f"[✗] Script not found: {script_path}")
        sys.exit(1)
    
    with open(script_path, 'r') as f:
        script_content = f.read()
    
    print(f"[*] Spawning DASHER app: {bundle_id}")
    print("[*] Applying analytics comprehensive spoofing...")
    print()
    
    try:
        # Spawn app with script
        pid = device.spawn([bundle_id])
        session = device.attach(pid)
        
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()
        
        device.resume(pid)
        
        print("[✓] DASHER app started with analytics fix!")
        print()
        print("="*60)
        print("IMPORTANT STEPS:")
        print("1. Wait for app to fully load")
        print("2. Navigate to dash screen")
        print("3. Tap 'Dash Now'")
        print()
        print("Expected: No error message!")
        print("="*60)
        print()
        print("Console output (watch for 'Modified analytics key' messages):")
        print()
        
        # Keep script running
        sys.stdin.read()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    except Exception as e:
        print(f"[✗] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()