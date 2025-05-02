# Kali NetHunter Kernel for Samsung Galaxy Tab S7 FE (SM-T733)

A custom Kali NetHunter kernel optimized for Samsung Galaxy Tab S7 FE (SM-T733) running LineageOS 22.1, designed to enhance penetration testing capabilities and device performance.

## Overview

This project provides a custom kernel for the Samsung Galaxy Tab S7 FE that enhances the device with Kali NetHunter features for security testing and penetration testing work. The kernel is built with specific modifications to support:

- **HID Attacks**: Human Interface Device functionality for BadUSB attacks
- **WiFi Monitoring & Injection**: Enhanced wireless capabilities for network security testing
- **USB Gadget Support**: Multiple USB device emulation (RNDIS, ECM, Mass Storage, etc.)
- **All Standard NetHunter Features**: Compatible with the full Kali NetHunter suite

## Prerequisites

To build this kernel, you'll need:

- Linux-based system (Ubuntu recommended)
- Git
- Python 3
- Build essentials (gcc, make, etc.)
- ARM64 cross-compiler toolchain
- At least 25GB free disk space
- About 8GB RAM

## Directory Structure

```
nethunter/
├── kernel_config.ini     # Configuration file for kernel build
├── kernel/               # LineageOS kernel source (will be cloned)
├── output/               # Built kernel images are stored here
├── patches/              # NetHunter-specific patches
│   ├── hid_support.patch             # For HID/BadUSB functionality
│   ├── wifi_injection.patch          # For WiFi monitor mode and packet injection
│   ├── usb_gadget.patch              # For enhanced USB gadget support
│   ├── battery_optimization.patch    # For battery optimization features
│   ├── tool_stability.patch          # For tool stability enhancements
│   └── enhanced_packet_injection.patch # Advanced packet injection features
├── tools/                # Build scripts and utilities
│   ├── build_kernel.sh           # Main build script
│   └── create_boot_img.sh        # Script to create flashable boot.img
└── visualization/        # Network packet analysis tools
    ├── nethunter_packet_visualizer.py  # Interactive GUI visualizer
    ├── nethunter_cli_visualizer.py     # Command-line visualizer
    ├── nethunter_pcap_to_html.py       # PCAP to HTML converter
    └── setup.sh                        # Dependency installation script
```

## Building the Kernel

1. **Clone this repository**:
   ```bash
   git clone https://github.com/tornado86/nethunter-kernel-sm-t733.git
   cd nethunter-sm-t733
   ```

2. **Review kernel configuration**:
   Check and modify `kernel_config.ini` if needed:
   ```ini
   [kernel]
   name=nethunter-sm-t733
   device=SM-T733
   codename=gts7fe
   lineage_branch=lineage-22
   kernel_source=https://github.com/Bush-cat/android_kernel_samsung_sm7325
   clone_depth=1
   defconfig=sm7325-gts7fewifi_defconfig

   [nethunter]
   add_hid=true
   add_wifi_injection=true
   add_usb_gadgets=true
   add_all_features=true
   ```

3. **Make build script executable**:
   ```bash
   chmod +x tools/build_kernel.sh
   ```

4. **Build the kernel**:
   ```bash
   ./tools/build_kernel.sh
   ```

5. **Output**: .n5u
 be available in the `output/` directory.

## Creating Flashable Boot Image

After building the kernel, you'll need to create a flashable boot image:

1. **Get stock boot.img**:
   Extract the stock boot.img from your device or from the LineageOS ROM package.

2. **Make script executable**:
   ```bash
   chmod +x tools/create_boot_img.sh
   ```

3. **Create boot image**:
   ```bash
   ./tools/create_boot_img.sh --stock /path/to/stock/boot.img
   ```

4. **Output**:
   This will create two files in the `output/` directory:
   - `NetHunter-gts7fe-boot.img`: Direct fastboot flashable image
   - `NetHunter-gts7fe-flashable.zip`: Recovery flashable ZIP package

For detailed instructions, see the [Boot Image Creation Guide](BOOT_IMAGE_GUIDE.md).

## Installation

1. **Prerequisites**:
   - Unlocked bootloader on your Samsung Galaxy Tab S7 FE (SM-T733)
   - LineageOS 22.1 installed
   - TWRP or similar custom recovery

2. **Install via Fastboot**:
   ```bash
   # Boot into fastboot mode
   adb reboot bootloader
   
   # Flash the boot image
   fastboot flash boot output/NetHunter-gts7fe-boot.img
   
   # Reboot the device
   fastboot reboot
   ```

3. **Install via Custom Recovery**:
   - Boot into TWRP or LineageOS Recovery
   - Flash the `NetHunter-gts7fe-flashable.zip` file
   - Reboot your device

4. **Install via Kali NetHunter App**:
   - Install the Kali NetHunter app from the F-Droid store
   - Go to Kernel Manager
   - Select "Custom Kernel" and browse to the kernel file
   - Flash and reboot

## Features

### HID (BadUSB) Support

The kernel includes USB HID functionality, allowing the tablet to emulate keyboard and mouse devices. This is essential for BadUSB attacks and penetration testing.

### WiFi Monitor Mode & Packet Injection

Enhanced wireless capabilities include:
- Monitor mode for capturing wireless traffic
- Packet injection for wireless security testing
- Support for wireless tools like Aircrack-ng, Kismet, and Wireshark

### USB Gadget Support

The kernel supports multiple USB device emulations:
- RNDIS (USB Ethernet)
- ECM (Ethernet Control Model)
- Mass Storage
- Serial
- ACM (Abstract Control Model)
- MIDI
- Multiple configuration support

## Troubleshooting

### Common Issues

1. **Kernel Fails to Boot**:
   - Boot back into TWRP
   - Flash the stock boot image

2. **WiFi Not Working**:
   - Check that the correct WiFi driver modules are loaded
   - Some features like monitor mode may require specific commands to activate

3. **USB Gadgets Not Working**:
   - Check that the USB connection is in OTG mode
   - Use NetHunter app to configure gadget settings

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the GPL v3 License - see the LICENSE file for details.

## Acknowledgments

- Kali NetHunter team for their work on mobile penetration testing
- LineageOS for providing the base kernel source
- All contributors to open-source mobile security tools
