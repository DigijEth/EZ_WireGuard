# WireGuard Server Setup GUI for Windows 11

A comprehensive Python GUI application for setting up and managing WireGuard VPN servers on Windows 11, with cross-platform client support.

![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2011-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🌟 Features

### Server Management
- **Automated WireGuard server setup** on Windows 11
- **Auto-detection** of network settings (public IP, local IP, gateway, DNS)
- **Automatic PATH configuration** for WireGuard installation
- **Key generation** for server and clients
- **Windows firewall** configuration
- **IP forwarding** enablement

### Client Management
- **Multi-client support** with unique configurations
- **Automatic IP assignment** for VPN tunnel addresses
- **Export client packages** with OS-specific installation scripts
- **QR code generation** for mobile clients (optional)

### Supported Client Platforms
- ✅ Windows (Batch script with Chocolatey/direct install)
- ✅ Ubuntu/Debian (APT package manager)
- ✅ Arch Linux (Pacman package manager)
- ✅ macOS (Homebrew or App Store)
- ✅ Android (Play Store with QR code import)
- ✅ iOS (App Store with QR code import)

## 📋 Requirements

### System Requirements
- **Windows 11** (or Windows 10 with latest updates)
- **Administrator privileges** (required for network configuration)
- **Python 3.6+** installed

### Software Requirements
- **WireGuard for Windows** - [Download](https://www.wireguard.com/install/)
  - Default installation path: `C:\Program Files\WireGuard`
  - Can be installed manually or via the script

### Python Dependencies
- **No external dependencies required!** Uses only Python standard library:
  - `tkinter` - GUI framework (included with Python)
  - `subprocess` - System commands
  - `socket` - Network operations
  - `urllib` - Public IP detection
  - `zipfile` - Client package exports
  - Other standard libraries

### Optional Dependencies
```bash
# For QR code generation (mobile clients)
pip install qrcode pillow
```

## 🚀 Installation

### Step 1: Install Python
Download and install Python 3.6+ from [python.org](https://www.python.org/downloads/)

### Step 2: Install WireGuard
Download and install WireGuard from [wireguard.com](https://www.wireguard.com/install/)

### Step 3: Download the Script
```bash
# Clone or download the script
git clone https://github.com/yourusername/wireguard-gui.git
cd wireguard-gui

# Or simply download wg_assist.py directly
```

### Step 4: Run as Administrator
```bash
# Right-click and "Run as Administrator" or use:
python wg_assist.py
```

## 📖 Usage Guide

### Initial Setup

1. **Launch the Application**
   - Run the script as Administrator
   - The script will auto-detect WireGuard installation
   - Network settings are detected automatically on startup

2. **Configure WireGuard Path** (if needed)
   - Click "Browse" to select WireGuard installation directory
   - Click "Verify Installation" to test

3. **Setup Server**
   - Review auto-detected network settings
   - Modify VPN subnet if needed (default: 10.0.0.1/24)
   - Click "Generate Server Keys"
   - Click "Setup WireGuard Server"
   - Click "Start Server"

### Adding Clients

1. **Generate Client Configuration**
   - Go to "Client Management" tab
   - Enter client name
   - VPN IP auto-increments (10.0.0.2, 10.0.0.3, etc.)
   - Click "Generate Client Config"

2. **Export Client Package**
   - Select client from dropdown
   - Choose target OS
   - Click "Export Client Package"
   - Choose save location
   - Send ZIP file to client

### Understanding IP Addresses

⚠️ **Important Concept:**

- **VPN Network IP** (e.g., 10.0.0.1/24): Internal VPN subnet, separate from your LAN
- **Client VPN IP** (e.g., 10.0.0.2/32): Fixed tunnel IP for each client
- **Public IP**: Your internet-facing IP that clients connect to
- **Local IP**: Your computer's LAN address (not used by clients)

Clients can connect from ANY network and always receive the same VPN tunnel IP.

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│         Windows 11 Server           │
│  ┌─────────────────────────────┐   │
│  │   WireGuard Server GUI      │   │
│  │  - Interface: wg_server     │   │
│  │  - VPN Net: 10.0.0.1/24     │   │
│  │  - Port: 51820              │   │
│  └─────────────────────────────┘   │
│                                     │
│  Public IP: xxx.xxx.xxx.xxx        │
└─────────────────────────────────────┘
              │
              │ Internet
              │
    ┌─────────┴──────────┬──────────┐
    │                    │          │
┌───▼───┐         ┌──────▼───┐  ┌───▼───┐
│Client1│         │ Client2  │  │Client3│
│10.0.0.2│        │10.0.0.3  │  │10.0.0.4│
│Windows│         │  Linux   │  │  iOS  │
└────────┘        └──────────┘  └────────┘
```

## 📦 Exported Client Package Contents

Each client export contains:

```
client_name_OS_WireGuard_Setup.zip
├── client_name.conf          # WireGuard configuration
├── setup_wireguard.*         # OS-specific installer script
├── README.txt               # Setup instructions
├── client_name_QR.png       # QR code (if available)
└── OS_SETUP.txt            # Platform-specific guide
```

### Installation Scripts by Platform

| OS | Script | Package Manager | Method |
|---|---|---|---|
| Windows | `setup_wireguard.bat` | Chocolatey/Direct | Auto-install + import |
| Ubuntu/Debian | `setup_wireguard_debian.sh` | APT | apt install wireguard |
| Arch Linux | `setup_wireguard_arch.sh` | Pacman | pacman -S wireguard-tools |
| macOS | `setup_wireguard_macos.sh` | Homebrew/App Store | brew install or GUI |
| Android | Instructions | Play Store | QR code import |
| iOS | Instructions | App Store | QR code import |

## 🔧 Configuration Files

### Server Configuration Location
- WireGuard Data Dir: `C:\Program Files\WireGuard\Data\Configurations\`
- Fallback: `./wireguard_configs/`

### Client Configurations
- Stored in: `./wireguard_clients/`
- Format: `client_name.conf`

## 🛠️ Troubleshooting

### Common Issues

**"WireGuard not found"**
- Install WireGuard from [wireguard.com](https://www.wireguard.com/install/)
- Set correct path in GUI
- Click "Verify Installation"

**"Admin privileges required"**
- Right-click script → Run as Administrator
- Required for firewall rules and network config

**"Port already in use"**
- Script auto-detects available ports
- Default: 51820, alternates: 51821-51825

**"Cannot detect public IP"**
- Check internet connection
- Firewall may block detection services
- Manually enter public IP/domain

**"Generate Keys button not working"**
- Verify WireGuard installation
- Check WireGuard path is correct
- Ensure wg.exe exists in the path

### Logs
- Check the "Logs" tab for detailed operation info
- Console output shows [LOG] and [STATUS] messages

## 🔒 Security Notes

- **Keep .conf files secure** - They contain private keys
- **Each client needs unique keys** - Never share configurations
- **Use strong endpoint authentication** - Consider additional security layers
- **Regular key rotation** - Regenerate keys periodically
- **Monitor connections** - Check logs for unauthorized access

## 📝 Advanced Configuration

### Custom VPN Subnets
Avoid conflicts with existing networks:
- If LAN uses 192.168.x.x → Use 10.0.0.0/24 for VPN
- If LAN uses 10.x.x.x → Use 172.16.0.0/24 for VPN
- If LAN uses 172.16.x.x → Use 10.0.0.0/24 for VPN

### Split Tunneling
Modify client's `AllowedIPs` for selective routing:
- Full tunnel: `0.0.0.0/0` (all traffic through VPN)
- Split tunnel: `10.0.0.0/24` (only VPN subnet)
- Custom: `10.0.0.0/24, 192.168.1.0/24` (specific subnets)

### Port Forwarding
For clients behind NAT, ensure:
- UDP port (default 51820) forwarded to server
- Windows Firewall allows WireGuard
- Router forwards UDP traffic

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

### Development Setup
```bash
# Clone repository
git clone https://github.com/yourusername/wireguard-gui.git
cd wireguard-gui

# Run in development
python wg_assist.py
```

### Areas for Contribution
- [ ] Linux server support
- [ ] Real-time traffic monitoring
- [ ] Client connection status dashboard
- [ ] Automatic key rotation
- [ ] DNS-over-HTTPS support
- [ ] IPv6 support
- [ ] Multi-language support

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- WireGuard® is a registered trademark of Jason A. Donenfeld
- Built with Python and tkinter
- Network detection using standard Windows utilities

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check the Troubleshooting section
- Review WireGuard documentation at [wireguard.com](https://www.wireguard.com/)

---

**Disclaimer:** This tool is provided as-is. Always review security implications before deploying VPN infrastructure.

**Note:** Ensure compliance with your organization's security policies and local regulations when deploying VPN services.
