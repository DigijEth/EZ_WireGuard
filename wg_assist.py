#!/usr/bin/env python3
"""
WireGuard Server Setup GUI for Windows 11
Requires WireGuard to be installed from https://www.wireguard.com/install/
Uses only Python standard library - no additional packages needed

Features:
- Auto-detect network settings and WireGuard installation
- Generate server and client configurations
- Export client packages with OS-specific installation scripts
- Support for Windows, Linux, macOS, Android, and iOS clients
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import os
import random
import ipaddress
import json
import winreg
import socket
import urllib.request
import zipfile
import shutil
from datetime import datetime
from pathlib import Path


class WireGuardServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WireGuard Server Setup - Windows 11")
        self.root.geometry("800x600")

        # Check if running as admin
        self.check_admin()

        # Server configuration storage
        self.server_config = {}
        self.clients = []

        # WireGuard path - try to auto-detect
        self.wireguard_path = self.find_wireguard_installation()

        # Check and setup WireGuard PATH
        self.check_wireguard_path()

        # Create UI
        self.create_widgets()

        # Auto-detect network settings after UI is ready
        self.root.after(1000, self.auto_detect_network)

    def check_admin(self):
        """Check if script is running with administrator privileges"""
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                messagebox.showwarning("Admin Required",
                                       "This script requires administrator privileges.\n"
                                       "Please run as administrator.")
        except:
            pass

    def find_wireguard_installation(self):
        """Try to find WireGuard installation path"""
        possible_paths = [
            r"C:\Program Files\WireGuard",
            r"C:\Program Files (x86)\WireGuard",
            r"D:\Program Files\WireGuard",
            r"D:\Program Files (x86)\WireGuard",
        ]

        # Check common installation paths
        for path in possible_paths:
            if os.path.exists(os.path.join(path, "wg.exe")):
                print(f"[INFO] Found WireGuard at: {path}")
                return path

        # Check if wg is in PATH already
        try:
            result = subprocess.run("where wg", capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                wg_location = result.stdout.strip().split('\n')[0]
                if wg_location:
                    path = os.path.dirname(wg_location)
                    print(f"[INFO] Found WireGuard in PATH at: {path}")
                    return path
        except:
            pass

        # Default to standard location
        return r"C:\Program Files\WireGuard"

    def check_wireguard_path(self):
        """Check if WireGuard is in PATH and add it if not"""
        # Try to run wg command
        try:
            result = subprocess.run("wg version", shell=True, capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return  # WireGuard is already in PATH
        except:
            pass

        # Check if WireGuard exists in default location
        wireguard_path = self.wireguard_path
        wg_exe = os.path.join(wireguard_path, "wg.exe")
        wireguard_exe = os.path.join(wireguard_path, "wireguard.exe")

        if not os.path.exists(wg_exe) or not os.path.exists(wireguard_exe):
            messagebox.showwarning("WireGuard Not Found",
                                   f"WireGuard not found in {wireguard_path}\n"
                                   "Please install WireGuard from https://www.wireguard.com/install/\n"
                                   "or set the correct path in the GUI.")
            return

        # Add to PATH for current session
        current_path = os.environ.get('PATH', '')
        if wireguard_path not in current_path:
            os.environ['PATH'] = f"{wireguard_path};{current_path}"

            # Also try to add to system PATH permanently (requires admin)
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                                    0, winreg.KEY_READ | winreg.KEY_WRITE) as key:

                    current_system_path, _ = winreg.QueryValueEx(key, "Path")

                    if wireguard_path not in current_system_path:
                        new_path = f"{current_system_path};{wireguard_path}"
                        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)

                        # Broadcast WM_SETTINGCHANGE to notify other processes
                        import ctypes
                        HWND_BROADCAST = 0xFFFF
                        WM_SETTINGCHANGE = 0x001A
                        ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment")

                        messagebox.showinfo("PATH Updated",
                                            f"WireGuard has been added to system PATH:\n{wireguard_path}")
            except Exception as e:
                # If we can't update system PATH, at least we have it for current session
                print(f"Could not update system PATH: {e}")

    def browse_wireguard_path(self):
        """Browse for WireGuard installation directory"""
        directory = filedialog.askdirectory(
            title="Select WireGuard Installation Directory",
            initialdir=self.wg_path_var.get()
        )
        if directory:
            self.wg_path_var.set(directory)
            self.wireguard_path = directory
            self.log(f"WireGuard path set to: {directory}")
            # Update PATH with new location
            current_path = os.environ.get('PATH', '')
            if directory not in current_path:
                os.environ['PATH'] = f"{directory};{current_path}"
            self.verify_wireguard_installation()

    def verify_wireguard_installation(self):
        """Verify WireGuard is properly installed at the specified path"""
        wg_path = self.wg_path_var.get()
        wg_exe = os.path.join(wg_path, "wg.exe")
        wireguard_exe = os.path.join(wg_path, "wireguard.exe")

        if os.path.exists(wg_exe) and os.path.exists(wireguard_exe):
            # Try to get version
            try:
                result = subprocess.run(f'"{wg_exe}" version', capture_output=True, text=True, shell=True)
                if result.returncode == 0:
                    version = result.stdout.strip()
                    self.log(f"WireGuard verified: {version}")
                    messagebox.showinfo("Verification Successful",
                                        f"WireGuard found and working!\n{version}")
                    return True
            except Exception as e:
                self.log(f"Error verifying WireGuard: {e}")

        self.log(f"WireGuard not found at: {wg_path}")
        messagebox.showerror("Verification Failed",
                             f"WireGuard not found at:\n{wg_path}\n\n"
                             "Please ensure:\n"
                             "1. WireGuard is installed\n"
                             "2. The path is correct\n"
                             "3. wg.exe and wireguard.exe exist in the directory")
        return False

    def get_local_ip(self):
        """Get the local IP address of the machine"""
        try:
            # Create a socket to external address (doesn't actually connect)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return None

    def get_public_ip(self):
        """Get the public IP address"""
        try:
            # Try multiple services for redundancy
            services = [
                'https://api.ipify.org',
                'https://ipinfo.io/ip',
                'https://icanhazip.com',
                'https://ident.me'
            ]

            for service in services:
                try:
                    with urllib.request.urlopen(service, timeout=5) as response:
                        public_ip = response.read().decode('utf8').strip()
                        # Validate it's an IP
                        socket.inet_aton(public_ip)
                        return public_ip
                except:
                    continue
            return None
        except:
            return None

    def get_default_gateway(self):
        """Get the default gateway address"""
        try:
            # Method 1: Use PowerShell (most reliable on Windows)
            ps_cmd = "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"
            result = subprocess.run(["powershell", "-Command", ps_cmd],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                gateway = result.stdout.strip()
                if gateway and gateway != '0.0.0.0':
                    try:
                        socket.inet_aton(gateway)
                        return gateway
                    except:
                        pass

            # Method 2: Parse ipconfig output
            result = subprocess.run("ipconfig", capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Default Gateway' in line:
                        # Extract IP address from the line
                        # Format is usually "Default Gateway . . . . . . : 192.168.1.1"
                        parts = line.split(':')
                        if len(parts) > 1:
                            gateway = parts[1].strip()
                            if gateway and gateway != '':
                                # Validate it's an IP
                                try:
                                    socket.inet_aton(gateway)
                                    return gateway
                                except:
                                    pass

            # Method 3: Use route print
            result = subprocess.run("route print 0.0.0.0", capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and 'On-link' not in line:
                        parts = line.split()
                        for part in parts:
                            # Look for IP-like strings
                            if '.' in part and part.count('.') == 3:
                                try:
                                    socket.inet_aton(part)
                                    if part != '0.0.0.0' and not part.startswith('127.'):
                                        return part
                                except:
                                    pass
            return None
        except Exception as e:
            self.log(f"Error detecting gateway: {str(e)}")
            return None

    def get_active_dns_servers(self):
        """Get currently active DNS servers"""
        try:
            # Get DNS servers from netsh
            result = subprocess.run("netsh interface ip show dnsservers",
                                    capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                dns_servers = []
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    # Look for lines that contain IP addresses
                    parts = line.split()
                    for part in parts:
                        try:
                            socket.inet_aton(part)
                            if part not in dns_servers:
                                dns_servers.append(part)
                        except:
                            pass

                if dns_servers:
                    return ', '.join(dns_servers[:2])  # Return first 2 DNS servers

            # Default to common DNS if can't detect
            return "8.8.8.8, 8.8.4.4"
        except:
            return "8.8.8.8, 8.8.4.4"

    def check_port_availability(self):
        """Check if WireGuard default port is available"""
        port = 51820
        try:
            # Try to bind to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('', port))
            sock.close()
            return "51820"
        except:
            # Port in use, try alternatives
            for alt_port in [51821, 51822, 51823, 51824, 51825]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind(('', alt_port))
                    sock.close()
                    return str(alt_port)
                except:
                    continue
            return "51820"  # Return default anyway

    def auto_detect_network(self):
        """Auto-detect network settings"""
        # Check if all required widgets exist
        if not hasattr(self, 'local_ip_display'):
            print("[DEBUG] Widgets not ready yet, postponing auto-detect")
            self.root.after(1000, self.auto_detect_network)
            return

        self.update_status("Detecting network settings...")
        self.log("Starting network auto-detection...")

        # Detect local IP
        local_ip = self.get_local_ip()
        if local_ip:
            self.local_ip_display.config(state="normal")
            self.local_ip_display.delete(0, tk.END)
            self.local_ip_display.insert(0, local_ip)
            self.local_ip_display.config(state="readonly")
            self.log(f"Local IP detected: {local_ip}")

            # Suggest VPN subnet based on local network
            if local_ip.startswith("192.168."):
                suggested_vpn = "10.0.0.1/24"
            elif local_ip.startswith("10."):
                suggested_vpn = "172.16.0.1/24"
            else:
                suggested_vpn = "10.0.0.1/24"

            self.server_ip.delete(0, tk.END)
            self.server_ip.insert(0, suggested_vpn)
            self.log(f"Suggested VPN subnet: {suggested_vpn}")
        else:
            self.log("Could not detect local IP")

        # Detect public IP
        self.log("Detecting public IP (this may take a moment)...")
        public_ip = self.get_public_ip()
        if public_ip:
            self.public_ip_display.config(state="normal")
            self.public_ip_display.delete(0, tk.END)
            self.public_ip_display.insert(0, public_ip)
            self.public_ip_display.config(state="readonly")

            # Update the public endpoint field
            self.public_endpoint.delete(0, tk.END)
            self.public_endpoint.insert(0, public_ip)

            self.log(f"Public IP detected: {public_ip}")
            self.server_config['public_ip'] = public_ip
        else:
            self.log("Could not detect public IP - you may be offline or behind strict firewall")
            self.public_endpoint.delete(0, tk.END)
            self.public_endpoint.insert(0, "MANUAL_ENTRY_REQUIRED")

        # Detect default gateway
        gateway = self.get_default_gateway()
        if gateway:
            self.gateway_display.config(state="normal")
            self.gateway_display.delete(0, tk.END)
            self.gateway_display.insert(0, gateway)
            self.gateway_display.config(state="readonly")
            self.log(f"Default gateway detected: {gateway}")
        else:
            self.log("Could not detect default gateway")

        # Detect DNS servers
        dns_servers = self.get_active_dns_servers()
        self.dns_servers.delete(0, tk.END)
        self.dns_servers.insert(0, dns_servers)
        self.log(f"DNS servers detected: {dns_servers}")

        # Detect available port (check if default 51820 is free)
        port = self.check_port_availability()
        if port != "51820":
            self.listen_port.delete(0, tk.END)
            self.listen_port.insert(0, port)
            self.log(f"Port {port} selected (51820 was in use)")
        else:
            self.log(f"Default port 51820 is available")

        self.update_status("Network detection complete")
        self.log("Network auto-detection completed successfully")

        messagebox.showinfo("Network Detection Complete",
                            f"Detected Settings:\n"
                            f"Local IP: {local_ip or 'Not detected'}\n"
                            f"Public IP: {public_ip or 'Not detected'}\n"
                            f"Gateway: {gateway or 'Not detected'}\n"
                            f"DNS: {dns_servers}\n"
                            f"Port: {port}")

    def create_widgets(self):
        """Create the GUI elements"""

        # Main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Server Setup Tab
        server_frame = ttk.Frame(notebook)
        notebook.add(server_frame, text="Server Setup")

        # WireGuard Path Configuration
        path_frame = ttk.LabelFrame(server_frame, text="WireGuard Installation", padding=10)
        path_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(path_frame, text="WireGuard Path:").grid(row=0, column=0, sticky="w", pady=5)
        self.wg_path_var = tk.StringVar(value=self.wireguard_path)
        self.wg_path_entry = ttk.Entry(path_frame, textvariable=self.wg_path_var, width=50)
        self.wg_path_entry.grid(row=0, column=1, pady=5, padx=5)

        self.browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_wireguard_path)
        self.browse_btn.grid(row=0, column=2, pady=5, padx=5)

        self.verify_btn = ttk.Button(path_frame, text="Verify Installation", command=self.verify_wireguard_installation)
        self.verify_btn.grid(row=1, column=1, pady=5)

        # Server Configuration
        config_frame = ttk.LabelFrame(server_frame, text="Server Configuration", padding=10)
        config_frame.pack(fill="x", padx=10, pady=10)

        # Interface Name
        ttk.Label(config_frame, text="Interface Name:").grid(row=0, column=0, sticky="w", pady=5)
        self.interface_name = ttk.Entry(config_frame, width=30)
        self.interface_name.insert(0, "wg_server")
        self.interface_name.grid(row=0, column=1, pady=5)

        # Server IP Address
        ttk.Label(config_frame, text="VPN Network (CIDR):").grid(row=1, column=0, sticky="w", pady=5)
        self.server_ip = ttk.Entry(config_frame, width=30)
        self.server_ip.insert(0, "10.0.0.1/24")
        self.server_ip.grid(row=1, column=1, pady=5)

        # Add help text for VPN network field
        vpn_help = ttk.Label(config_frame, text="Internal VPN subnet (e.g., 10.0.0.0/24), not your public IP",
                             font=('TkDefaultFont', 8), foreground='gray')
        vpn_help.grid(row=2, column=1, sticky="w")

        # Listen Port
        ttk.Label(config_frame, text="Listen Port:").grid(row=3, column=0, sticky="w", pady=5)
        self.listen_port = ttk.Entry(config_frame, width=30)
        self.listen_port.insert(0, "51820")
        self.listen_port.grid(row=3, column=1, pady=5)

        # DNS Servers
        ttk.Label(config_frame, text="DNS Servers:").grid(row=4, column=0, sticky="w", pady=5)
        self.dns_servers = ttk.Entry(config_frame, width=30)
        self.dns_servers.insert(0, "8.8.8.8, 8.8.4.4")
        self.dns_servers.grid(row=4, column=1, pady=5)

        # Public Endpoint (for clients)
        ttk.Label(config_frame, text="Public IP/Domain:").grid(row=5, column=0, sticky="w", pady=5)
        self.public_endpoint = ttk.Entry(config_frame, width=30)
        self.public_endpoint.insert(0, "Auto-detect required")
        self.public_endpoint.grid(row=5, column=1, pady=5)

        # Auto-detect button
        self.detect_btn = ttk.Button(config_frame, text="Auto-Detect Network Settings",
                                     command=self.auto_detect_network)
        self.detect_btn.grid(row=6, column=0, columnspan=2, pady=10)

        # Generate Keys Button
        self.gen_keys_btn = ttk.Button(config_frame, text="Generate Server Keys",
                                       command=self.generate_server_keys)
        self.gen_keys_btn.grid(row=7, column=0, columnspan=2, pady=10)

        # Keys Display
        keys_frame = ttk.LabelFrame(server_frame, text="Server Keys", padding=10)
        keys_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(keys_frame, text="Private Key:").grid(row=0, column=0, sticky="w")
        self.private_key_display = ttk.Entry(keys_frame, width=60, state="readonly")
        self.private_key_display.grid(row=0, column=1, padx=5)

        ttk.Label(keys_frame, text="Public Key:").grid(row=1, column=0, sticky="w")
        self.public_key_display = ttk.Entry(keys_frame, width=60, state="readonly")
        self.public_key_display.grid(row=1, column=1, padx=5)

        # Network Info Display
        network_frame = ttk.LabelFrame(server_frame, text="Network Information", padding=10)
        network_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(network_frame, text="Local IP:").grid(row=0, column=0, sticky="w")
        self.local_ip_display = ttk.Entry(network_frame, width=30, state="readonly")
        self.local_ip_display.grid(row=0, column=1, padx=5)

        ttk.Label(network_frame, text="Public IP:").grid(row=1, column=0, sticky="w")
        self.public_ip_display = ttk.Entry(network_frame, width=30, state="readonly")
        self.public_ip_display.grid(row=1, column=1, padx=5)

        ttk.Label(network_frame, text="Default Gateway:").grid(row=2, column=0, sticky="w")
        self.gateway_display = ttk.Entry(network_frame, width=30, state="readonly")
        self.gateway_display.grid(row=2, column=1, padx=5)

        # Action Buttons
        action_frame = ttk.Frame(server_frame)
        action_frame.pack(fill="x", padx=10, pady=10)

        self.setup_btn = ttk.Button(action_frame, text="Setup WireGuard Server",
                                    command=self.setup_server, state="disabled")
        self.setup_btn.pack(side="left", padx=5)

        self.start_btn = ttk.Button(action_frame, text="Start Server",
                                    command=self.start_server, state="disabled")
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(action_frame, text="Stop Server",
                                   command=self.stop_server, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        # Client Management Tab
        client_frame = ttk.Frame(notebook)
        notebook.add(client_frame, text="Client Management")

        # Add Client Section
        add_client_frame = ttk.LabelFrame(client_frame, text="Add New Client", padding=10)
        add_client_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(add_client_frame, text="Client Name:").grid(row=0, column=0, sticky="w", pady=5)
        self.client_name = ttk.Entry(add_client_frame, width=30)
        self.client_name.grid(row=0, column=1, pady=5)

        ttk.Label(add_client_frame, text="VPN IP (Internal):").grid(row=1, column=0, sticky="w", pady=5)
        self.client_ip = ttk.Entry(add_client_frame, width=30)
        self.client_ip.insert(0, "10.0.0.2/32")
        self.client_ip.grid(row=1, column=1, pady=5)

        # Add help text for IP field
        help_text = ttk.Label(add_client_frame,
                              text="This is the client's internal VPN IP, not their physical network IP",
                              font=('TkDefaultFont', 8), foreground='gray')
        help_text.grid(row=2, column=1, sticky="w")

        self.add_client_btn = ttk.Button(add_client_frame, text="Generate Client Config",
                                         command=self.generate_client_config, state="disabled")
        self.add_client_btn.grid(row=3, column=0, columnspan=2, pady=10)

        # Client List
        list_frame = ttk.LabelFrame(client_frame, text="Client Configurations", padding=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.client_list = scrolledtext.ScrolledText(list_frame, height=8, width=80)
        self.client_list.pack(fill="both", expand=True)

        # Export Client Section
        export_frame = ttk.LabelFrame(client_frame, text="Export Client Setup", padding=10)
        export_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(export_frame, text="Select Client:").grid(row=0, column=0, sticky="w", pady=5)
        self.export_client_combo = ttk.Combobox(export_frame, width=30, state="readonly")
        self.export_client_combo.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(export_frame, text="Client OS:").grid(row=1, column=0, sticky="w", pady=5)
        self.client_os = ttk.Combobox(export_frame, width=30, state="readonly")
        self.client_os['values'] = ('Windows', 'Ubuntu/Debian', 'Arch Linux', 'macOS', 'Android', 'iOS')
        self.client_os.set('Windows')
        self.client_os.grid(row=1, column=1, pady=5, padx=5)

        self.export_client_btn = ttk.Button(export_frame, text="Export Client Package",
                                            command=self.export_client_package, state="disabled")
        self.export_client_btn.grid(row=2, column=0, columnspan=2, pady=10)

        # Logs Tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Logs")

        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, width=80)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Status Bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def log(self, message):
        """Add message to log display"""
        # Check if log_text exists before trying to use it
        if hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, f"{message}\n")
            self.log_text.see(tk.END)
            self.root.update()
        print(f"[LOG] {message}")  # Also print to console for debugging

    def update_status(self, message):
        """Update status bar"""
        if hasattr(self, 'status_bar'):
            self.status_bar.config(text=message)
            self.root.update()
        print(f"[STATUS] {message}")  # Also print to console

    def run_command(self, command, shell=True):
        """Run a system command and return output"""
        try:
            self.log(f"Running command: {command}")
            result = subprocess.run(command, shell=shell, capture_output=True, text=True)
            if result.returncode == 0:
                return True, result.stdout
            else:
                self.log(f"Command failed with error: {result.stderr}")
                return False, result.stderr
        except Exception as e:
            self.log(f"Exception running command: {str(e)}")
            return False, str(e)

    def generate_server_keys(self):
        """Generate WireGuard server keys"""
        self.update_status("Generating server keys...")
        self.log("Starting server key generation...")

        # Get the WireGuard path from the field
        wg_path = os.path.join(self.wg_path_var.get(), "wg.exe")
        if not os.path.exists(wg_path):
            messagebox.showerror("Error",
                                 f"WireGuard not found at: {wg_path}\n"
                                 "Please set the correct path and verify installation.")
            return

        # Generate private key
        try:
            result = subprocess.run(f'"{wg_path}" genkey', capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                self.log(f"Error generating private key: {result.stderr}")
                messagebox.showerror("Error", f"Failed to generate private key: {result.stderr}")
                return
            private_key = result.stdout.strip()
        except Exception as e:
            self.log(f"Exception generating private key: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate private key: {str(e)}")
            return

        # Generate public key from private key
        try:
            # Use echo with pipe to pass private key to wg pubkey
            cmd = f'echo {private_key} | "{wg_path}" pubkey'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                self.log(f"Error generating public key: {result.stderr}")
                messagebox.showerror("Error", f"Failed to generate public key: {result.stderr}")
                return
            public_key = result.stdout.strip()
        except Exception as e:
            self.log(f"Exception generating public key: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate public key: {str(e)}")
            return

        # Store and display keys
        self.server_config['private_key'] = private_key
        self.server_config['public_key'] = public_key

        self.private_key_display.config(state="normal")
        self.private_key_display.delete(0, tk.END)
        self.private_key_display.insert(0, private_key)
        self.private_key_display.config(state="readonly")

        self.public_key_display.config(state="normal")
        self.public_key_display.delete(0, tk.END)
        self.public_key_display.insert(0, public_key)
        self.public_key_display.config(state="readonly")

        self.log("Server keys generated successfully")
        self.log(f"Private key: {private_key[:20]}...")
        self.log(f"Public key: {public_key[:20]}...")
        self.setup_btn.config(state="normal")
        self.update_status("Server keys generated")

    def setup_server(self):
        """Setup WireGuard server configuration"""
        self.update_status("Setting up WireGuard server...")

        # Verify WireGuard is available at the set path
        if not self.verify_wireguard_installation():
            return

        # Get configuration values
        interface = self.interface_name.get()
        server_ip = self.server_ip.get()
        port = self.listen_port.get()
        private_key = self.server_config.get('private_key')

        if not private_key:
            messagebox.showerror("Error", "Please generate server keys first")
            return

        # Create configuration directory (use WireGuard's Data directory if it exists)
        wg_data_dir = os.path.join(self.wg_path_var.get(), "Data", "Configurations")
        if os.path.exists(os.path.dirname(wg_data_dir)):
            config_dir = Path(wg_data_dir)
        else:
            # Fallback to local directory
            config_dir = Path("wireguard_configs")

        config_dir.mkdir(parents=True, exist_ok=True)

        # Create server configuration file
        config_file = config_dir / f"{interface}.conf"

        config_content = f"""# WireGuard Server Configuration
# Generated by WireGuard Setup GUI

[Interface]
# The server's private key for encryption
PrivateKey = {private_key}

# The server's IP address in the VPN network (not the public IP)
# This creates a virtual network separate from your LAN
Address = {server_ip}

# UDP port WireGuard listens on
ListenPort = {port}

# PostUp and PostDown rules can be added here for NAT/firewall
# PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
"""

        try:
            with open(config_file, 'w') as f:
                f.write(config_content)
            self.log(f"Configuration saved to {config_file}")
        except Exception as e:
            self.log(f"Error saving configuration: {e}")
            return

        # Setup Windows firewall rules
        self.setup_firewall_rules(port)

        # Enable IP forwarding
        self.enable_ip_forwarding()

        self.server_config['interface'] = interface
        self.server_config['config_file'] = str(config_file)

        self.start_btn.config(state="normal")
        self.add_client_btn.config(state="normal")
        self.update_status("Server setup complete")

    def setup_firewall_rules(self, port):
        """Configure Windows firewall rules for WireGuard"""
        self.log("Setting up firewall rules...")

        # Add inbound rule
        cmd = f'netsh advfirewall firewall add rule name="WireGuard-In" dir=in action=allow protocol=UDP localport={port}'
        success, output = self.run_command(cmd)
        if success:
            self.log("Inbound firewall rule added")
        else:
            self.log(f"Warning: Could not add inbound rule: {output}")

        # Add outbound rule
        cmd = f'netsh advfirewall firewall add rule name="WireGuard-Out" dir=out action=allow protocol=UDP localport={port}'
        success, output = self.run_command(cmd)
        if success:
            self.log("Outbound firewall rule added")
        else:
            self.log(f"Warning: Could not add outbound rule: {output}")

    def enable_ip_forwarding(self):
        """Enable IP forwarding on Windows"""
        self.log("Enabling IP forwarding...")

        cmd = 'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f'
        success, output = self.run_command(cmd)
        if success:
            self.log("IP forwarding enabled")
        else:
            self.log(f"Warning: Could not enable IP forwarding: {output}")

        # Restart routing service
        cmd = 'sc stop RemoteAccess & sc start RemoteAccess'
        self.run_command(cmd)

    def start_server(self):
        """Start WireGuard server"""
        interface = self.server_config.get('interface')
        config_file = self.server_config.get('config_file')

        if not interface or not config_file:
            messagebox.showerror("Error", "Server not configured")
            return

        self.update_status(f"Starting WireGuard server on {interface}...")

        # Get WireGuard.exe path
        wireguard_exe = os.path.join(self.wg_path_var.get(), "wireguard.exe")
        if not os.path.exists(wireguard_exe):
            messagebox.showerror("Error",
                                 f"wireguard.exe not found at: {wireguard_exe}\n"
                                 "Please set the correct path and verify installation.")
            return

        # Install and start WireGuard tunnel
        cmd = f'"{wireguard_exe}" /installtunnelservice "{config_file}"'
        success, output = self.run_command(cmd)

        if success:
            self.log(f"WireGuard server started on interface {interface}")
            self.stop_btn.config(state="normal")
            self.start_btn.config(state="disabled")
            self.update_status("Server running")
        else:
            self.log(f"Error starting server: {output}")

    def stop_server(self):
        """Stop WireGuard server"""
        interface = self.server_config.get('interface')

        if not interface:
            return

        self.update_status(f"Stopping WireGuard server on {interface}...")

        # Get WireGuard.exe path
        wireguard_exe = os.path.join(self.wg_path_var.get(), "wireguard.exe")
        if not os.path.exists(wireguard_exe):
            messagebox.showerror("Error",
                                 f"wireguard.exe not found at: {wireguard_exe}\n"
                                 "Please set the correct path and verify installation.")
            return

        cmd = f'"{wireguard_exe}" /uninstalltunnelservice {interface}'
        success, output = self.run_command(cmd)

        if success:
            self.log(f"WireGuard server stopped")
            self.stop_btn.config(state="disabled")
            self.start_btn.config(state="normal")
            self.update_status("Server stopped")
        else:
            self.log(f"Error stopping server: {output}")

    def generate_client_config(self):
        """Generate client configuration"""
        client_name = self.client_name.get()
        client_ip = self.client_ip.get()

        if not client_name:
            messagebox.showerror("Error", "Please enter a client name")
            return

        self.update_status(f"Generating configuration for {client_name}...")

        # Get the WireGuard path from the field
        wg_path = os.path.join(self.wg_path_var.get(), "wg.exe")
        if not os.path.exists(wg_path):
            messagebox.showerror("Error",
                                 f"WireGuard not found at: {wg_path}\n"
                                 "Please set the correct path and verify installation.")
            return

        # Generate client keys
        try:
            result = subprocess.run(f'"{wg_path}" genkey', capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                self.log(f"Error generating client private key: {result.stderr}")
                return
            client_private_key = result.stdout.strip()
        except Exception as e:
            self.log(f"Exception generating client private key: {str(e)}")
            return

        try:
            cmd = f'echo {client_private_key} | "{wg_path}" pubkey'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                self.log(f"Error generating client public key: {result.stderr}")
                return
            client_public_key = result.stdout.strip()
        except Exception as e:
            self.log(f"Exception generating client public key: {str(e)}")
            return

        # Generate preshared key
        try:
            result = subprocess.run(f'"{wg_path}" genpsk', capture_output=True, text=True, shell=True)
            psk = result.stdout.strip() if result.returncode == 0 else ""
        except:
            psk = ""

        # Get server public IP from the field or config
        server_public_ip = self.public_endpoint.get()
        if not server_public_ip or server_public_ip == "Auto-detect required" or server_public_ip == "MANUAL_ENTRY_REQUIRED":
            messagebox.showerror("Error",
                                 "Please run 'Auto-Detect Network Settings' first or manually enter the public IP/domain")
            return

        # Create client configuration
        client_config = f"""[Interface]
# This is the VPN tunnel IP address for this client, not their physical network IP
# The client can connect from any network (home, office, mobile) and will always
# get this same internal VPN IP address
PrivateKey = {client_private_key}
Address = {client_ip}
DNS = {self.dns_servers.get()}

[Peer]
# Server configuration
PublicKey = {self.server_config.get('public_key')}
PresharedKey = {psk}

# AllowedIPs determines what traffic goes through the VPN tunnel:
# 0.0.0.0/0 = Route ALL internet traffic through VPN (full tunnel)
# To route only specific traffic through VPN, you could use:
# - 10.0.0.0/24 = Only traffic to VPN network
# - 10.0.0.0/24, 192.168.1.0/24 = VPN network + specific LAN
AllowedIPs = 0.0.0.0/0

# Server's public endpoint - this is where the client connects to
# The client can be behind any NAT/firewall and connect to this public IP
Endpoint = {server_public_ip}:{self.listen_port.get()}

# Keep connection alive through NAT/firewalls (ping every 25 seconds)
PersistentKeepalive = 25
"""

        # Save client configuration
        config_dir = Path("wireguard_clients")
        config_dir.mkdir(exist_ok=True)

        client_file = config_dir / f"{client_name}.conf"
        with open(client_file, 'w') as f:
            f.write(client_config)

        # Store client info for export
        client_info = {
            'name': client_name,
            'config_file': str(client_file),
            'config_content': client_config,
            'public_key': client_public_key,
            'ip': client_ip
        }
        self.clients.append(client_info)

        # Update export client dropdown
        client_names = [c['name'] for c in self.clients]
        self.export_client_combo['values'] = client_names
        if len(client_names) == 1:
            self.export_client_combo.set(client_names[0])
        self.export_client_btn.config(state="normal")

        # Update server configuration to add client as peer
        self.add_client_peer(client_name, client_public_key, client_ip, psk)

        # Display client info
        self.client_list.insert(tk.END, f"\n--- {client_name} ---\n")
        self.client_list.insert(tk.END, f"Public Key: {client_public_key}\n")
        self.client_list.insert(tk.END, f"IP: {client_ip}\n")
        self.client_list.insert(tk.END, f"Config saved to: {client_file}\n")

        self.log(f"Client configuration generated for {client_name}")
        self.update_status(f"Client {client_name} added")

        # Clear input fields
        self.client_name.delete(0, tk.END)

        # Increment IP for next client
        try:
            ip_obj = ipaddress.ip_interface(client_ip)
            next_ip = ip_obj.ip + 1
            self.client_ip.delete(0, tk.END)
            self.client_ip.insert(0, f"{next_ip}/32")
        except:
            pass

    def add_client_peer(self, name, public_key, allowed_ips, psk):
        """Add client as peer to server configuration"""
        config_file = self.server_config.get('config_file')
        if not config_file:
            return

        peer_config = f"""
[Peer]
# {name}
PublicKey = {public_key}
PresharedKey = {psk}
AllowedIPs = {allowed_ips}
"""

        try:
            with open(config_file, 'a') as f:
                f.write(peer_config)
            self.log(f"Added {name} to server configuration")

            # If server is running, reload configuration
            if self.stop_btn['state'] == 'normal':
                interface = self.server_config.get('interface')
                wg_path = os.path.join(self.wg_path_var.get(), "wg.exe")
                if os.path.exists(wg_path):
                    self.run_command(f'"{wg_path}" syncconf {interface} "{config_file}"')
                    self.log(f"Reloaded server configuration")
        except Exception as e:
            self.log(f"Error updating server configuration: {e}")

    def export_client_package(self):
        """Export client configuration with OS-specific installation scripts"""
        selected_client = self.export_client_combo.get()
        selected_os = self.client_os.get()

        if not selected_client:
            messagebox.showerror("Error", "Please select a client to export")
            return

        # Find the client info
        client_info = None
        for client in self.clients:
            if client['name'] == selected_client:
                client_info = client
                break

        if not client_info:
            messagebox.showerror("Error", "Client configuration not found")
            return

        # Ask where to save the export package
        export_dir = filedialog.askdirectory(title=f"Select Export Location for {selected_client}")
        if not export_dir:
            return

        self.log(f"Exporting client package for {selected_client} ({selected_os})...")

        # Create package directory
        package_name = f"{selected_client}_{selected_os.replace('/', '_').replace(' ', '_')}_WireGuard_Setup"
        package_dir = Path(export_dir) / package_name
        package_dir.mkdir(exist_ok=True)

        # Copy configuration file
        config_file = package_dir / f"{selected_client}.conf"
        with open(config_file, 'w') as f:
            f.write(client_info['config_content'])

        # Create OS-specific installation script
        if selected_os == 'Windows':
            self.create_windows_setup(package_dir, selected_client)
            self.log("Created Windows setup batch script")
        elif selected_os == 'Ubuntu/Debian':
            self.create_ubuntu_setup(package_dir, selected_client)
            self.log("Created Ubuntu/Debian setup script")
        elif selected_os == 'Arch Linux':
            self.create_arch_setup(package_dir, selected_client)
            self.log("Created Arch Linux setup script")
        elif selected_os == 'macOS':
            self.create_macos_setup(package_dir, selected_client)
            self.log("Created macOS setup script")
        elif selected_os == 'Android':
            self.create_android_instructions(package_dir, selected_client)
            self.log("Created Android setup instructions")
        elif selected_os == 'iOS':
            self.create_ios_instructions(package_dir, selected_client)
            self.log("Created iOS setup instructions")

        # Create README
        self.create_readme(package_dir, selected_client, selected_os, client_info)
        self.log("Created README file")

        # List all files in package directory for debugging
        package_files = list(package_dir.glob('*'))
        self.log(f"Package contains {len(package_files)} files:")
        for file in package_files:
            self.log(f"  - {file.name}")

        # Create ZIP archive
        zip_path = Path(export_dir) / f"{package_name}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in package_dir.rglob('*'):
                if file.is_file():
                    zipf.write(file, file.relative_to(package_dir))

        self.log(f"Client package exported to: {zip_path}")
        messagebox.showinfo("Export Complete",
                            f"Client setup package exported successfully!\n\n"
                            f"Location: {zip_path}\n\n"
                            f"The package contains:\n"
                            f"• WireGuard configuration file\n"
                            f"• Installation script for {selected_os}\n"
                            f"• Setup instructions")

        # Open the export directory
        try:
            os.startfile(export_dir)
        except:
            pass  # startfile only works on Windows

    def create_windows_setup(self, package_dir, client_name):
        """Create Windows setup batch script"""
        setup_script = package_dir / "setup_wireguard.bat"
        content = f"""@echo off
title WireGuard Client Setup - {client_name}
color 0A
echo ===============================================
echo     WireGuard Client Setup for Windows
echo     Client: {client_name}
echo ===============================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges!
    echo Please run as Administrator.
    pause
    exit /b 1
)

echo [1] Checking if WireGuard is installed...
where wireguard >nul 2>&1
if %errorLevel% equ 0 (
    echo WireGuard is already installed!
    goto :import_config
)

echo [2] WireGuard not found. Installing WireGuard...
echo.

:: Check if Chocolatey is installed
where choco >nul 2>&1
if %errorLevel% equ 0 (
    echo Using Chocolatey to install WireGuard...
    choco install wireguard -y
    goto :check_install
)

:: Download WireGuard installer directly
echo Chocolatey not found. Downloading WireGuard installer...
echo.
set "DOWNLOAD_URL=https://download.wireguard.com/windows-client/wireguard-installer.exe"
set "INSTALLER=wireguard-installer.exe"

powershell -Command "Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%INSTALLER%'"

if exist %INSTALLER% (
    echo Installing WireGuard...
    %INSTALLER% /silent
    timeout /t 10 /nobreak >nul
    del %INSTALLER%
) else (
    echo Failed to download WireGuard installer!
    echo Please install WireGuard manually from: https://www.wireguard.com/install/
    pause
    exit /b 1
)

:check_install
where wireguard >nul 2>&1
if %errorLevel% neq 0 (
    echo WireGuard installation failed!
    echo Please install manually from: https://www.wireguard.com/install/
    pause
    exit /b 1
)

:import_config
echo.
echo [3] Importing WireGuard configuration...
set "CONFIG_FILE={client_name}.conf"

if not exist "%CONFIG_FILE%" (
    echo Configuration file not found: %CONFIG_FILE%
    echo Please ensure the .conf file is in the same directory as this script.
    pause
    exit /b 1
)

:: Import the configuration
echo Importing configuration: %CONFIG_FILE%
set "WG_PATH=C:\\Program Files\\WireGuard\\wireguard.exe"
if exist "%WG_PATH%" (
    "%WG_PATH%" /installtunnelservice "%CD%\\%CONFIG_FILE%"
) else (
    echo WireGuard executable not found at expected location.
    echo Trying to import manually...
    wireguard /installtunnelservice "%CD%\\%CONFIG_FILE%"
)

echo.
echo ===============================================
echo     Setup Complete!
echo ===============================================
echo.
echo WireGuard has been installed and configured.
echo.
echo To manage your VPN connection:
echo 1. Open WireGuard from the Start Menu or System Tray
echo 2. Your tunnel "{client_name}" should appear in the list
echo 3. Click "Activate" to connect to the VPN
echo.
echo To start automatically with Windows:
echo - Right-click the tunnel in WireGuard
echo - Select "Properties"
echo - Check "Start on boot"
echo.
pause
"""
        with open(setup_script, 'w') as f:
            f.write(content)

    def create_ubuntu_setup(self, package_dir, client_name):
        """Create Ubuntu/Debian setup script"""
        setup_script = package_dir / "setup_wireguard_debian.sh"  # Clear name for Debian/Ubuntu
        content = f"""#!/bin/bash
# WireGuard Client Setup Script for Ubuntu/Debian
# Client: {client_name}

set -e

echo "======================================="
echo "  WireGuard Client Setup for Ubuntu/Debian"
echo "  Client: {client_name}"
echo "======================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

echo "[1] Updating package list..."
apt update

echo ""
echo "[2] Installing WireGuard..."
apt install -y wireguard wireguard-tools

echo ""
echo "[3] Setting up configuration..."
CONFIG_FILE="{client_name}.conf"
DEST_CONFIG="/etc/wireguard/{client_name}.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file not found: $CONFIG_FILE"
    echo "Please ensure the .conf file is in the same directory as this script."
    exit 1
fi

# Copy configuration to WireGuard directory
cp "$CONFIG_FILE" "$DEST_CONFIG"
chmod 600 "$DEST_CONFIG"
chown root:root "$DEST_CONFIG"

echo ""
echo "[4] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo ""
echo "======================================="
echo "        Setup Complete!"
echo "======================================="
echo ""
echo "WireGuard has been installed and configured."
echo ""
echo "Available commands:"
echo "  Start VPN:    sudo wg-quick up {client_name}"
echo "  Stop VPN:     sudo wg-quick down {client_name}"
echo "  Show status:  sudo wg show"
echo ""
echo "To start VPN automatically on boot:"
echo "  sudo systemctl enable wg-quick@{client_name}"
echo ""
echo "Would you like to start the VPN now? (y/n)"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    wg-quick up {client_name}
    echo ""
    echo "VPN is now connected!"
    echo ""
    wg show
fi
"""
        with open(setup_script, 'w', newline='\n') as f:  # Force Unix line endings
            f.write(content)

        # Make script executable (for when extracted on Linux)
        os.chmod(setup_script, 0o755)
        self.log(f"Created Ubuntu/Debian setup script: setup_wireguard_debian.sh")

    def create_arch_setup(self, package_dir, client_name):
        """Create Arch Linux setup script"""
        setup_script = package_dir / "setup_wireguard_arch.sh"  # Unique name for Arch
        content = f"""#!/bin/bash
# WireGuard Client Setup Script for Arch Linux
# Client: {client_name}

set -e

echo "======================================="
echo "  WireGuard Client Setup for Arch Linux"
echo "  Client: {client_name}"
echo "======================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

echo "[1] Updating package database..."
pacman -Sy

echo ""
echo "[2] Installing WireGuard..."
pacman -S --noconfirm wireguard-tools

echo ""
echo "[3] Setting up configuration..."
CONFIG_FILE="{client_name}.conf"
DEST_CONFIG="/etc/wireguard/{client_name}.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file not found: $CONFIG_FILE"
    echo "Please ensure the .conf file is in the same directory as this script."
    exit 1
fi

# Create WireGuard directory if it doesn't exist
mkdir -p /etc/wireguard

# Copy configuration to WireGuard directory
cp "$CONFIG_FILE" "$DEST_CONFIG"
chmod 600 "$DEST_CONFIG"
chown root:root "$DEST_CONFIG"

echo ""
echo "[4] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf

echo ""
echo "[5] Loading WireGuard kernel module..."
modprobe wireguard || echo "Note: WireGuard module may be built-in to kernel"

echo ""
echo "======================================="
echo "        Setup Complete!"
echo "======================================="
echo ""
echo "WireGuard has been installed and configured."
echo ""
echo "Available commands:"
echo "  Start VPN:    sudo wg-quick up {client_name}"
echo "  Stop VPN:     sudo wg-quick down {client_name}"
echo "  Show status:  sudo wg show"
echo ""
echo "To start VPN automatically on boot:"
echo "  sudo systemctl enable wg-quick@{client_name}"
echo ""
echo "Would you like to start the VPN now? (y/n)"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    wg-quick up {client_name}
    echo ""
    echo "VPN is now connected!"
    echo ""
    wg show
fi
"""
        with open(setup_script, 'w', newline='\n') as f:  # Force Unix line endings
            f.write(content)

        # Make script executable (sets permission bits for when extracted on Linux)
        os.chmod(setup_script, 0o755)
        self.log(f"Created Arch Linux setup script: setup_wireguard_arch.sh")

    def create_macos_setup(self, package_dir, client_name):
        """Create macOS setup script"""
        setup_script = package_dir / "setup_wireguard_macos.sh"  # Clear name for macOS
        content = f"""#!/bin/bash
# WireGuard Client Setup Script for macOS
# Client: {client_name}

echo "======================================="
echo "  WireGuard Client Setup for macOS"
echo "  Client: {client_name}"
echo "======================================="
echo ""

# Function to check if command exists
command_exists() {{
    command -v "$1" >/dev/null 2>&1
}}

echo "[1] Checking installation method..."

# Check if Homebrew is installed
if command_exists brew; then
    echo "Homebrew detected. Installing WireGuard via Homebrew..."
    brew install wireguard-tools

    echo ""
    echo "[2] Setting up configuration..."
    CONFIG_FILE="{client_name}.conf"
    DEST_CONFIG="/usr/local/etc/wireguard/{client_name}.conf"

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    # Create WireGuard directory if it doesn't exist
    sudo mkdir -p /usr/local/etc/wireguard

    # Copy configuration
    sudo cp "$CONFIG_FILE" "$DEST_CONFIG"
    sudo chmod 600 "$DEST_CONFIG"

    echo ""
    echo "======================================="
    echo "        Setup Complete!"
    echo "======================================="
    echo ""
    echo "WireGuard has been installed via Homebrew."
    echo ""
    echo "To use WireGuard from command line:"
    echo "  Start VPN:    sudo wg-quick up {client_name}"
    echo "  Stop VPN:     sudo wg-quick down {client_name}"
    echo "  Show status:  sudo wg show"
else
    echo "Homebrew not found."
    echo ""
    echo "RECOMMENDED: Install WireGuard from the Mac App Store"
    echo ""
    echo "Instructions:"
    echo "1. Open the Mac App Store"
    echo "2. Search for 'WireGuard'"
    echo "3. Install the WireGuard app (by WireGuard Development Team)"
    echo "4. Open WireGuard from Applications"
    echo "5. Click 'Import tunnel(s) from file'"
    echo "6. Select the {client_name}.conf file"
    echo "7. Click 'Activate' to connect"
    echo ""
    echo "Alternative: Install Homebrew first, then run this script again"
    echo "Install Homebrew from: https://brew.sh"
fi

echo ""
echo "Configuration file location: {client_name}.conf"
echo ""
echo "For GUI application (recommended):"
echo "1. Install WireGuard from Mac App Store"
echo "2. Import the {client_name}.conf file"
echo ""
"""
        with open(setup_script, 'w', newline='\n') as f:  # Force Unix line endings
            f.write(content)

        os.chmod(setup_script, 0o755)
        self.log(f"Created macOS setup script: setup_wireguard_macos.sh")

    def create_android_instructions(self, package_dir, client_name):
        """Create Android setup instructions"""
        instructions = package_dir / "ANDROID_SETUP.txt"
        content = f"""WireGuard Setup Instructions for Android
Client: {client_name}
=========================================

INSTALLATION STEPS:

1. Install WireGuard App:
   - Open Google Play Store
   - Search for "WireGuard"
   - Install the app by "WireGuard Development Team"
   - Or visit: https://play.google.com/store/apps/details?id=com.wireguard.android

2. Import Configuration:

   Method A - QR Code (Easiest):
   - Open WireGuard app
   - Tap the "+" button
   - Select "Create from QR code"
   - Use the QR code provided (if available)

   Method B - File Import:
   - Transfer the {client_name}.conf file to your Android device
   - Open WireGuard app
   - Tap the "+" button
   - Select "Import from file"
   - Navigate to and select {client_name}.conf
   - Give the tunnel a name (or keep default)

3. Connect to VPN:
   - Toggle the switch next to your tunnel name to ON
   - Accept the VPN connection request (first time only)
   - You should see "Active" status

4. Optional Settings:
   - Long press on the tunnel name for options
   - You can enable "Auto-start on boot"
   - You can exclude certain apps from VPN

TROUBLESHOOTING:

- If connection fails, check your internet connection
- Ensure the server is running and accessible
- Try toggling airplane mode and reconnecting
- Check if your mobile carrier blocks VPN connections

SECURITY NOTE:
Keep your configuration file secure. Anyone with this file
can connect to your VPN server using your credentials.
"""
        with open(instructions, 'w') as f:
            f.write(content)

        # Try to generate QR code if qrcode library is available
        try:
            import qrcode
            qr = qrcode.QRCode(version=None, box_size=10, border=5)
            with open(package_dir / f"{client_name}.conf", 'r') as f:
                config_content = f.read()
            qr.add_data(config_content)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(package_dir / f"{client_name}_QR.png")

            with open(instructions, 'a') as f:
                f.write(f"\n\nQR CODE:\nA QR code has been generated: {client_name}_QR.png\n"
                        "You can scan this directly with the WireGuard Android app.\n")
            self.log("QR code generated for mobile setup")
        except ImportError:
            self.log("Note: Install 'qrcode' and 'pillow' packages for QR code generation")
            with open(instructions, 'a') as f:
                f.write("\n\nNOTE: QR code generation requires 'pip install qrcode pillow'\n")

    def create_ios_instructions(self, package_dir, client_name):
        """Create iOS setup instructions"""
        instructions = package_dir / "iOS_SETUP.txt"
        content = f"""WireGuard Setup Instructions for iOS (iPhone/iPad)
Client: {client_name}
==================================================

INSTALLATION STEPS:

1. Install WireGuard App:
   - Open the App Store
   - Search for "WireGuard"
   - Install the app by "WireGuard Development Team"
   - Or visit: https://apps.apple.com/us/app/wireguard/id1441195209

2. Import Configuration:

   Method A - QR Code (Easiest):
   - Open WireGuard app
   - Tap "+" button
   - Select "Create from QR code"
   - Allow camera access
   - Scan the QR code provided (if available)
   - Name your tunnel and tap "Save"

   Method B - File Import:
   - Email yourself the {client_name}.conf file
   - Open the email on your iOS device
   - Tap and hold the .conf attachment
   - Select "Share" and choose "WireGuard"
   - Name your tunnel and tap "Save"

   Method C - Manual Entry:
   - Open WireGuard app
   - Tap "+" then "Add a tunnel manually"
   - Enter the configuration details from {client_name}.conf

3. Connect to VPN:
   - Toggle the switch next to your tunnel name to ON
   - Accept the VPN configuration request (first time only)
   - You should see "Active" status

4. Optional Settings:
   - Tap on the tunnel name for details
   - You can enable "Connect on Demand" for automatic connection
   - Set up rules for Wi-Fi or cellular connections

TROUBLESHOOTING:

- If connection fails, check your internet connection
- Ensure the server is running and accessible
- Try toggling airplane mode and reconnecting
- Check Settings > VPN to ensure configuration is present

SECURITY NOTE:
Keep your configuration file secure. Anyone with this file
can connect to your VPN server using your credentials.

For Face ID/Touch ID protection:
Settings > WireGuard > Use Face ID / Touch ID
"""
        with open(instructions, 'w') as f:
            f.write(content)

        # Try to generate QR code if qrcode library is available
        try:
            import qrcode
            qr = qrcode.QRCode(version=None, box_size=10, border=5)
            with open(package_dir / f"{client_name}.conf", 'r') as f:
                config_content = f.read()
            qr.add_data(config_content)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(package_dir / f"{client_name}_QR.png")

            with open(instructions, 'a') as f:
                f.write(f"\n\nQR CODE:\nA QR code has been generated: {client_name}_QR.png\n"
                        "You can scan this directly with the WireGuard iOS app.\n")
            self.log("QR code generated for mobile setup")
        except ImportError:
            self.log("Note: Install 'qrcode' and 'pillow' packages for QR code generation")
            with open(instructions, 'a') as f:
                f.write("\n\nNOTE: QR code generation requires 'pip install qrcode pillow'\n")

    def create_readme(self, package_dir, client_name, os_type, client_info):
        """Create a general README file"""
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Determine script name based on OS
        script_name = "setup_wireguard"
        if os_type == "Windows":
            script_name = "setup_wireguard.bat"
        elif os_type == "Ubuntu/Debian":
            script_name = "setup_wireguard_debian.sh"
        elif os_type == "Arch Linux":
            script_name = "setup_wireguard_arch.sh"
        elif os_type == "macOS":
            script_name = "setup_wireguard_macos.sh"
        elif os_type in ["Android", "iOS"]:
            script_name = f"{os_type.replace(' ', '_')}_SETUP.txt"

        client_vpn_ip = client_info.get('ip', '10.0.0.x/32')

        readme = package_dir / "README.txt"
        content = f"""WireGuard VPN Client Setup Package
===================================
Client Name: {client_name}
Target OS: {os_type}
Generated: {current_date}

PACKAGE CONTENTS:
-----------------
• {client_name}.conf - WireGuard configuration file (your VPN credentials)
• {script_name} - Automated installation script for {os_type}
• README.txt - This file
• OS-specific setup instructions (if applicable)

IMPORTANT - Understanding the IP Addresses:
--------------------------------------------
The configuration file contains "Address = {client_vpn_ip}"
This is your VPN TUNNEL IP, not your physical network IP.

• Your device's network IP (changes based on WiFi/network): Handled by DHCP
• Your VPN tunnel IP (always the same): {client_vpn_ip}

You can connect from ANY network (home, office, mobile data) and will always 
get the same VPN tunnel IP for routing within the VPN.

QUICK START:
------------
1. Extract all files to the same directory
2. Run the setup script for your operating system:
   - Windows: Right-click {script_name} and "Run as Administrator"
   - Linux/Mac: chmod +x {script_name} && sudo ./{script_name}
   - Mobile: Follow the instructions in the setup guide
3. The script will install WireGuard and import your configuration
4. Connect to the VPN using the WireGuard application

MANUAL SETUP:
-------------
If the automated script doesn't work:
1. Install WireGuard from: https://www.wireguard.com/install/
2. Import the {client_name}.conf file into WireGuard
3. Activate the connection

SECURITY NOTES:
---------------
• Keep your .conf file secure - it contains your private keys
• Do not share this file with others
• Delete this package after successful setup
• Each client should have its own unique configuration

SUPPORT:
--------
• WireGuard Documentation: https://www.wireguard.com/
• Platform-specific guides are included in this package

CONNECTION DETAILS:
-------------------
Once connected, you can verify your VPN connection by:
• Checking your IP address at: https://whatismyipaddress.com
• Running 'wg show' command (on Linux/Mac with admin privileges)
• Checking the WireGuard app status

Remember to disconnect from the VPN when not needed to conserve bandwidth.
"""
        with open(readme, 'w') as f:
            f.write(content)


def main():
    root = tk.Tk()
    app = WireGuardServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()