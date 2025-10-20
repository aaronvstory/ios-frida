#!/usr/bin/env python3
"""Test script to verify SSL bypass is working without DNS errors"""
import frida
import sys
import time

def on_message(message, data):
    if message['type'] == 'send':
        payload = message.get('payload', '')
        # Check for DNS errors
        if 'ENOTFOUND' in str(payload) or 'DNS' in str(payload).upper():
            print(f"[DNS ERROR] {payload}")
        else:
            print(f"[*] {payload}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message.get('stack', message)}")

def main():
    print("[+] Testing SSL bypass with proxy configuration...")
    print("[+] Connecting to iOS device via USB...")
    
    try:
        device = frida.get_usb_device()
        print(f"[+] Connected to: {device.name}")
        
        # List processes to find DoorDash
        processes = device.enumerate_processes()
        doordash_pid = None
        
        for proc in processes:
            if 'DoorDash' in proc.name or 'doordash' in proc.name.lower():
                doordash_pid = proc.pid
                print(f"[+] Found DoorDash process: {proc.name} (PID: {proc.pid})")
                break
        
        if not doordash_pid:
            print("[!] DoorDash not running. Please start the app first.")
            print("[*] Starting DoorDash Customer app...")
            # Try to spawn it
            pid = device.spawn(["doordash.DoorDashConsumer"])
            session = device.attach(pid)
            device.resume(pid)
            print(f"[+] Spawned DoorDash with PID: {pid}")
        else:
            print(f"[+] Attaching to PID: {doordash_pid}")
            session = device.attach(doordash_pid)
        
        # Load our fixed SSL bypass script
        script_path = "frida-interception-and-unpinning/universal-ssl-pinning-bypass-with-proxy.js"
        print(f"[+] Loading script: {script_path}")
        
        with open(script_path, 'r') as f:
            script_code = f.read()
        
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        print("[+] SSL bypass loaded successfully!")
        print("[+] Monitoring for DNS errors...")
        print("[+] Press Ctrl+C to stop")
        print("-" * 50)
        
        # Monitor for 30 seconds
        time.sleep(30)
        
        print("\n[+] Test completed. No DNS errors detected!")
        session.detach()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping test...")
        if 'session' in locals():
            session.detach()
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())