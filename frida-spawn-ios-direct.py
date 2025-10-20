#!/usr/bin/env python3
"""Spawn iOS app via direct network connection to frida-server"""
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
        print("Usage: python frida-spawn-ios-direct.py <bundle_id> <script_path> [host:port]")
        print("Example: python frida-spawn-ios-direct.py com.doordash.dasher script.js 192.168.50.130:27042")
        sys.exit(1)

    bundle_id = sys.argv[1]
    script_path = sys.argv[2]
    host_port = sys.argv[3] if len(sys.argv) > 3 else "192.168.50.130:27042"

    if not os.path.exists(script_path):
        print(f"[!] Script not found: {script_path}")
        sys.exit(1)

    print(f"[+] Bundle ID: {bundle_id}")
    print(f"[+] Script: {os.path.basename(script_path)}")
    print(f"[+] Frida server: {host_port}")

    try:
        # Connect to frida-server at specific host:port
        print("[+] Connecting to frida-server...")
        device_manager = frida.get_device_manager()
        device = device_manager.add_remote_device(host_port)
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

        print(f"\n[+] {bundle_id} spawned with PID: {pid}")
        print("[+] Script loaded and monitoring active")
        print("[+] Press Ctrl+C to stop.\n")
        print("=" * 60)

        # Keep the script running
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            session.detach()

    except frida.ServerNotRunningError:
        print(f"[!] Error: Cannot connect to frida-server at {host_port}")
        print("[!] Make sure frida-server is running on the iPhone")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
