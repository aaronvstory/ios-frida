#!/usr/bin/env python3
import frida
import sys
import os
import time

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python frida-spawn.py <bundle_id> <script_path>")
        sys.exit(1)
    
    bundle_id = sys.argv[1]
    script_path = sys.argv[2]

    # Use the script that was passed - don't override!
    # The PowerShell script already handles script selection
    if not os.path.exists(script_path):
        print(f"[!] Script not found: {script_path}")
        sys.exit(1)
    
    print(f"[+] Bundle ID: {bundle_id}")
    print(f"[+] Script: {os.path.basename(script_path)}")
    
    try:
        # Connect to USB device
        device = frida.get_usb_device()
        print(f"[+] Connected to device: {device.name}")
        
        # Spawn the app
        print(f"[+] Spawning {bundle_id}...")
        pid = device.spawn([bundle_id])
        session = device.attach(pid)
        
        # Load the script
        with open(script_path, 'r') as f:
            script_code = f.read()
        
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        # Resume the app
        device.resume(pid)
        
        print(f"[+] {bundle_id} spawned and script loaded. Press Ctrl+C to stop.")
        
        # Keep the script running
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            session.detach()
            
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()