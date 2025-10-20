#!/usr/bin/env python3
"""Spawn iOS app via remote Frida connection"""
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
        print("Usage: python frida-spawn-ios.py <bundle_id> <script_path>")
        sys.exit(1)

    bundle_id = sys.argv[1]
    script_path = sys.argv[2]

    if not os.path.exists(script_path):
        print(f"[!] Script not found: {script_path}")
        sys.exit(1)

    print(f"[+] Bundle ID: {bundle_id}")
    print(f"[+] Script: {os.path.basename(script_path)}")

    try:
        # Connect to remote frida-server (via network or SSH tunnel)
        print("[+] Connecting to remote device...")
        device = frida.get_remote_device()
        print(f"[+] Connected to device: {device.name}")

        # Spawn the app
        print(f"[+] Spawning {bundle_id}...")
        pid = device.spawn([bundle_id])
        session = device.attach(pid)

        # Load the script
        print("[+] Loading Frida script...")
        with open(script_path, 'r', encoding='utf-8') as f:
            script_code = f.read()

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        # Resume the app
        device.resume(pid)

        print(f"[+] {bundle_id} spawned and script loaded. Monitoring...")
        print("[+] Press Ctrl+C to stop.")
        print("")

        # Keep the script running
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            session.detach()

    except frida.ServerNotRunningError:
        print("[!] Error: Cannot connect to frida-server")
        print("[!] Make sure frida-server is running on the iPhone")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
