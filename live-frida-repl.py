#!/usr/bin/env python3
"""
Live Frida REPL - Interactive Frida scripting environment

This script provides a live, interactive environment for developing and testing
Frida scripts in real-time. Perfect for rapid prototyping and experimentation.

Usage:
    python live-frida-repl.py <app_identifier> [--spawn]

Examples:
    # Attach to running Dasher app
    python live-frida-repl.py com.doordash.driverapp

    # Spawn Dasher app
    python live-frida-repl.py com.doordash.driverapp --spawn

Features:
    - Live script editing and hot-reload
    - Save/load script templates
    - Network monitoring helpers
    - SSL unpinning helpers
    - Interactive JavaScript console
"""

import frida
import sys
import os
import argparse
import time
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class FridaREPL:
    def __init__(self, app_id, spawn_mode=False):
        self.app_id = app_id
        self.spawn_mode = spawn_mode
        self.device = None
        self.session = None
        self.script = None
        self.script_code = ""

    def log(self, msg, level="INFO"):
        """Colored logging"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "ERROR": Fore.RED,
            "WARNING": Fore.YELLOW,
            "SCRIPT": Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"{Fore.WHITE}[{timestamp}] {color}[{level}]{Style.RESET_ALL} {msg}")

    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict):
                msg_type = payload.get('type', 'info')
                msg_content = payload.get('message', payload)
                self.log(f"{msg_content}", "SCRIPT")
            else:
                self.log(f"{payload}", "SCRIPT")
        elif message['type'] == 'error':
            self.log(f"Error: {message.get('description', message)}", "ERROR")
            if 'stack' in message:
                print(f"{Fore.RED}{message['stack']}{Style.RESET_ALL}")

    def connect(self):
        """Connect to device and app"""
        try:
            # Get USB device
            self.log("Connecting to USB device...", "INFO")
            self.device = frida.get_usb_device()
            self.log(f"Connected to: {self.device.name} ({self.device.id})", "SUCCESS")

            # Spawn or attach
            if self.spawn_mode:
                self.log(f"Spawning {self.app_id}...", "INFO")
                pid = self.device.spawn([self.app_id])
                self.session = self.device.attach(pid)
                self.log(f"Spawned with PID: {pid}", "SUCCESS")
            else:
                self.log(f"Attaching to {self.app_id}...", "INFO")
                self.session = self.device.attach(self.app_id)
                self.log(f"Attached successfully", "SUCCESS")

            return True

        except frida.ProcessNotFoundError:
            self.log(f"App not running: {self.app_id}", "ERROR")
            self.log("Start the app or use --spawn mode", "INFO")
            return False
        except Exception as e:
            self.log(f"Connection error: {e}", "ERROR")
            return False

    def load_template(self, template_name):
        """Load a script template"""
        templates = {
            "basic": """
console.log("[*] Basic Frida script loaded");
console.log("[*] App: " + Java.androidVersion);
""",
            "network": """
console.log("[*] Network monitoring script loaded");

// Hook OkHttp3
Java.perform(function() {
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        console.log("[+] Found OkHttp3");

        var Request = Java.use('okhttp3.Request');
        Request.url.implementation = function() {
            var url = this.url();
            console.log("[REQUEST] " + url.toString());
            return url;
        };
    } catch(e) {
        console.log("[!] OkHttp3 not found: " + e);
    }

    // Hook HttpURLConnection
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getURL.implementation = function() {
            var url = this.getURL();
            console.log("[REQUEST] " + url.toString());
            return url;
        };
    } catch(e) {
        console.log("[!] HttpURLConnection hook failed: " + e);
    }
});
""",
            "ssl-unpin": """
console.log("[*] SSL unpinning script loaded");

Java.perform(function() {
    // SSLContext bypass
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            console.log("[+] SSLContext.init() bypassed");
            this.init(km, null, sr);
        };
    } catch(e) {
        console.log("[!] SSLContext bypass failed: " + e);
    }

    // TrustManager bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.frida.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });
        console.log("[+] Custom TrustManager registered");
    } catch(e) {
        console.log("[!] TrustManager bypass failed: " + e);
    }

    // OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] Certificate pinning bypassed for: " + hostname);
            return;
        };
    } catch(e) {
        console.log("[!] OkHttp3 CertificatePinner not found");
    }
});
""",
            "proxy": """
console.log("[*] Proxy configuration script loaded");

var proxyHost = "192.168.50.9";
var proxyPort = 8000;

Java.perform(function() {
    // Set system proxy
    try {
        var System = Java.use('java.lang.System');
        System.setProperty("http.proxyHost", proxyHost);
        System.setProperty("http.proxyPort", proxyPort.toString());
        System.setProperty("https.proxyHost", proxyHost);
        System.setProperty("https.proxyPort", proxyPort.toString());
        console.log("[+] System proxy set to " + proxyHost + ":" + proxyPort);
    } catch(e) {
        console.log("[!] System proxy setup failed: " + e);
    }

    // Hook OkHttpClient to add proxy
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        var Proxy = Java.use('java.net.Proxy');
        var Type = Java.use('java.net.Proxy$Type');
        var InetSocketAddress = Java.use('java.net.InetSocketAddress');

        Builder.build.implementation = function() {
            var client = this.build();
            var proxy = Proxy.$new(Type.HTTP.value, InetSocketAddress.$new(proxyHost, proxyPort));
            this.proxy(proxy);
            console.log("[+] OkHttpClient proxy configured");
            return this.build();
        };
    } catch(e) {
        console.log("[!] OkHttpClient proxy failed: " + e);
    }
});
""",
            "all": """
console.log("[*] Complete monitoring + SSL bypass + Proxy script loaded");

var proxyHost = "192.168.50.9";
var proxyPort = 8000;

Java.perform(function() {
    console.log("[*] Java environment ready");
    console.log("[*] Android version: " + Java.androidVersion);

    // SSL Unpinning
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            console.log("[+] SSLContext.init() bypassed");
            this.init(km, null, sr);
        };

        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] Certificate pinning bypassed for: " + hostname);
            return;
        };
    } catch(e) {}

    // Proxy Setup
    try {
        var System = Java.use('java.lang.System');
        System.setProperty("http.proxyHost", proxyHost);
        System.setProperty("http.proxyPort", proxyPort.toString());
        System.setProperty("https.proxyHost", proxyHost);
        System.setProperty("https.proxyPort", proxyPort.toString());
        console.log("[+] Proxy configured: " + proxyHost + ":" + proxyPort);
    } catch(e) {}

    // Network Monitoring
    try {
        var Request = Java.use('okhttp3.Request');
        Request.url.implementation = function() {
            var url = this.url();
            send({type: 'request', url: url.toString()});
            console.log("[→] " + url.toString());
            return url;
        };
    } catch(e) {}
});
"""
        }

        return templates.get(template_name, templates["basic"])

    def load_script(self, script_code):
        """Load and execute a Frida script"""
        try:
            if self.script:
                self.script.unload()

            self.script_code = script_code
            self.script = self.session.create_script(script_code)
            self.script.on('message', self.on_message)
            self.script.load()

            if self.spawn_mode:
                self.device.resume(self.session._impl.pid)

            self.log("Script loaded successfully", "SUCCESS")
            return True

        except Exception as e:
            self.log(f"Script load error: {e}", "ERROR")
            return False

    def interactive_mode(self):
        """Start interactive REPL"""
        self.log("=" * 60, "INFO")
        self.log("FRIDA LIVE REPL - Interactive Mode", "INFO")
        self.log("=" * 60, "INFO")
        print()
        print(f"{Fore.CYAN}Commands:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}load <template>{Style.RESET_ALL}  - Load script template (basic, network, ssl-unpin, proxy, all)")
        print(f"  {Fore.GREEN}reload{Style.RESET_ALL}            - Reload current script")
        print(f"  {Fore.GREEN}edit{Style.RESET_ALL}              - Edit script in nano/notepad")
        print(f"  {Fore.GREEN}save <file>{Style.RESET_ALL}       - Save current script")
        print(f"  {Fore.GREEN}run <file>{Style.RESET_ALL}        - Load and run script from file")
        print(f"  {Fore.GREEN}js <code>{Style.RESET_ALL}         - Execute JavaScript in app context")
        print(f"  {Fore.GREEN}quit{Style.RESET_ALL}              - Exit REPL")
        print()

        while True:
            try:
                cmd = input(f"{Fore.YELLOW}frida> {Style.RESET_ALL}").strip()

                if not cmd:
                    continue

                parts = cmd.split(maxsplit=1)
                action = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if action == "quit" or action == "exit":
                    self.log("Exiting REPL...", "INFO")
                    break

                elif action == "load":
                    template = arg or "basic"
                    script_code = self.load_template(template)
                    self.load_script(script_code)

                elif action == "reload":
                    self.load_script(self.script_code)

                elif action == "save":
                    if arg:
                        with open(arg, 'w') as f:
                            f.write(self.script_code)
                        self.log(f"Script saved to {arg}", "SUCCESS")
                    else:
                        self.log("Usage: save <filename>", "ERROR")

                elif action == "run":
                    if arg and os.path.exists(arg):
                        with open(arg, 'r') as f:
                            script_code = f.read()
                        self.load_script(script_code)
                    else:
                        self.log(f"File not found: {arg}", "ERROR")

                elif action == "js":
                    if arg:
                        wrapper = f"""
                        Java.perform(function() {{
                            {arg}
                        }});
                        """
                        temp_script = self.session.create_script(wrapper)
                        temp_script.on('message', self.on_message)
                        temp_script.load()
                    else:
                        self.log("Usage: js <JavaScript code>", "ERROR")

                elif action == "help":
                    print(f"\n{Fore.CYAN}Available templates:{Style.RESET_ALL}")
                    print("  basic     - Basic script template")
                    print("  network   - Network monitoring")
                    print("  ssl-unpin - SSL certificate unpinning")
                    print("  proxy     - Proxy configuration")
                    print("  all       - Complete monitoring + SSL + Proxy")
                    print()

                else:
                    self.log(f"Unknown command: {action}. Type 'help' for commands.", "ERROR")

            except KeyboardInterrupt:
                print()
                self.log("Use 'quit' to exit", "INFO")
            except Exception as e:
                self.log(f"Error: {e}", "ERROR")

    def run(self):
        """Main run loop"""
        if not self.connect():
            return 1

        # Auto-load default script
        self.log("Loading default 'all' template...", "INFO")
        default_script = self.load_template("all")
        self.load_script(default_script)

        # Start interactive mode
        self.interactive_mode()

        # Cleanup
        if self.session:
            self.session.detach()

        return 0

def main():
    parser = argparse.ArgumentParser(
        description='Live Frida REPL for interactive script development',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('app', help='App identifier (e.g., com.doordash.driverapp)')
    parser.add_argument('--spawn', action='store_true', help='Spawn app instead of attaching')

    args = parser.parse_args()

    repl = FridaREPL(args.app, args.spawn)
    sys.exit(repl.run())

if __name__ == "__main__":
    main()
