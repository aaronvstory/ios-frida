#!/usr/bin/env python3
import frida
import sys
import time

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] {message['stack']}")

# Connect to USB device
device = frida.get_usb_device()
print(f"[+] Connected to: {device.name}")

# Find DoorDash process
processes = device.enumerate_processes()
doordash = [p for p in processes if 'DasherApp' in p.name or 'DoorDash' in p.name]

if not doordash:
    print("[!] DoorDash not running. Starting it...")
    # Spawn the app
    pid = device.spawn(["doordash.DoorDashConsumer"])
    session = device.attach(pid)
    device.resume(pid)
    print(f"[+] Spawned DoorDash with PID: {pid}")
else:
    # Attach to existing
    pid = doordash[0].pid
    print(f"[+] Found DoorDash running with PID: {pid}")
    session = device.attach(pid)

# Load the WORKING script
with open(r"C:\claude\ios frida\frida-interception-and-unpinning\WORKING-ssl-bypass-with-proxy.js", 'r') as f:
    script_code = f.read()

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print("[+] Script loaded! Monitoring...")
print("[*] Press Ctrl+C to stop")

try:
    sys.stdin.read()
except KeyboardInterrupt:
    print("\n[*] Stopping...")
    session.detach()