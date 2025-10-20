#!/usr/bin/env python3
"""Restart frida-server on iPhone to listen on network"""
import paramiko
import time

def restart_frida():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print("[*] Connecting to iPhone via 3uTools tunnel...")
        ssh.connect(
            hostname='127.0.0.1',
            port=22,
            username='root',
            password='alpine',
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )
        print("[+] SSH connected!")

        # Kill existing frida-server
        print("[*] Stopping existing frida-server...")
        ssh.exec_command("killall frida-server")
        time.sleep(1)

        # Start frida-server listening on all interfaces
        print("[*] Starting frida-server on 0.0.0.0...")
        ssh.exec_command("nohup frida-server -l 0.0.0.0 > /dev/null 2>&1 &")
        time.sleep(2)

        # Verify it's running
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep frida-server | grep -v grep")
        result = stdout.read().decode()

        if result:
            print("[+] Frida-server restarted successfully!")
            print(result)
        else:
            print("[!] Failed to start frida-server")
            return False

        ssh.close()
        return True

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    restart_frida()
