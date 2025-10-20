#!/usr/bin/env python3
import frida
import sys
import os

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python frida-attach.py <pid> <script_path>")
        sys.exit(1)
    
    pid = int(sys.argv[1])
    script_path = sys.argv[2]
    
    # Only auto-replace script if it's the standard universal script
    # Don't override specific scripts like reset-to-stock.js
    script_name = os.path.basename(script_path)

    if script_name == "universal-ssl-pinning-bypass.js":
        # Use comprehensive SSL bypass for better coverage
        base_dir = os.path.dirname(script_path)
        comprehensive_script = os.path.join(base_dir, "comprehensive-ssl-pinning-bypass.js")
        proxy_script = script_path.replace("universal-ssl-pinning-bypass.js",
                                          "universal-ssl-pinning-bypass-with-proxy.js")

        # Priority: comprehensive > proxy > original
        if os.path.exists(comprehensive_script):
            script_path = comprehensive_script
            print(f"[+] Using comprehensive bypass: {os.path.basename(comprehensive_script)}")
        elif os.path.exists(proxy_script):
            script_path = proxy_script
            print(f"[+] Using proxy script: {os.path.basename(proxy_script)}")
    else:
        # Use the exact script specified (e.g., reset-to-stock.js)
        print(f"[+] Using specified script: {script_name}")
    
    print(f"[+] PID: {pid}")
    print(f"[+] Script: {os.path.basename(script_path)}")
    
    try:
        # Connect to USB device
        device = frida.get_usb_device()
        print(f"[+] Connected to device: {device.name}")
        
        # Attach to the process
        print(f"[+] Attaching to PID {pid}...")
        session = device.attach(pid)
        
        # Load the script
        with open(script_path, 'r') as f:
            script_code = f.read()
        
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        print(f"[+] Attached to PID {pid} and script loaded. Press Ctrl+C to stop.")
        
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