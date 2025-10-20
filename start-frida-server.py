#!/usr/bin/env python3
"""Start Frida server on iPhone via SSH tunnel"""
import paramiko
import time

def start_frida_server():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print("[*] Connecting to iPhone via SSH tunnel (127.0.0.1:22)...")
        ssh.connect(
            hostname='127.0.0.1',
            port=22,
            username='root',
            password='alpine',
            timeout=10
        )
        print("[+] SSH connected!")

        # Check if frida-server is already running
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep frida-server | grep -v grep")
        result = stdout.read().decode()

        if result:
            print("[+] Frida-server is already running!")
            print(result)
        else:
            print("[*] Starting frida-server...")
            # Start frida-server in background
            ssh.exec_command("nohup /usr/sbin/frida-server > /dev/null 2>&1 &")
            time.sleep(2)

            # Verify it started
            stdin, stdout, stderr = ssh.exec_command("ps aux | grep frida-server | grep -v grep")
            result = stdout.read().decode()

            if result:
                print("[+] Frida-server started successfully!")
                print(result)
            else:
                print("[!] Failed to start frida-server")
                return False

        ssh.close()
        return True

    except Exception as e:
        print(f"[!] Error: {e}")
        return False

if __name__ == "__main__":
    success = start_frida_server()
    if not success:
        print("\n[!] Make sure:")
        print("  1. 3uTools SSH tunnel is open")
        print("  2. Frida is installed on your iPhone")
        print("  3. frida-server binary is at /usr/sbin/frida-server")
        exit(1)
