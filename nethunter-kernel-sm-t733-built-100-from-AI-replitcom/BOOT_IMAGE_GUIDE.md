# NetHunter Boot Image Creation Guide

This guide explains how to build a flashable boot.img for your Samsung Galaxy Tab S7 FE (SM-T733) running LineageOS 22.1.

## Prerequisites

Before creating a boot image, you need:

1. A compiled NetHunter kernel
2. Original stock boot.img from your device (extracted from your current ROM)
3. ADB and Fastboot tools installed on your computer

## Step 1: Build the NetHunter Kernel

First, build the custom NetHunter kernel using the build script:

```bash
./tools/build_kernel.sh
```

This will compile the kernel with all the NetHunter features you've enabled in the `kernel_config.ini` file and generate the kernel image at `output/Image.gz-dtb`.

## Step 2: Extract Stock Boot Image

You need the original boot.img from your device to use as a template. There are two ways to obtain it:

### Option 1: Extract from running device (recommended)

If your device is already running LineageOS 22.1, you can extract the boot image directly:

1. Boot your device normally and enable Developer Options
2. Enable USB Debugging in Developer Options
3. Connect your device to your computer
4. Open a terminal and run:

```bash
# Create a backup of your current boot partition
adb shell "su -c 'dd if=/dev/block/bootdevice/by-name/boot of=/sdcard/boot.img bs=4096'"

# Pull the boot image to your computer
adb pull /sdcard/boot.img
```

### Option 2: Extract from LineageOS ZIP

If you have the LineageOS 22.1 ZIP file for your device:

1. Unzip the LineageOS ZIP file
2. Find and extract the boot.img file

## Step 3: Create Boot Image

Use the boot image creation script with your extracted stock boot.img:

```bash
./tools/create_boot_img.sh --stock /path/to/stock/boot.img
```

This script will:
1. Extract the necessary components from the stock boot image
2. Replace the kernel with your NetHunter kernel
3. Repack everything into a new boot image
4. Create a flashable ZIP file for easy installation

The output files will be saved to:
- `output/NetHunter-gts7fe-boot.img` - Direct Fastboot flashable image
- `output/NetHunter-gts7fe-flashable.zip` - Recovery flashable ZIP

## Step 4: Flash the New Boot Image

You have two options to flash the new kernel:

### Option 1: Using Fastboot (recommended for developers)

1. Boot your device into fastboot mode:
   ```bash
   adb reboot bootloader
   ```

2. Flash the boot image:
   ```bash
   fastboot flash boot output/NetHunter-gts7fe-boot.img
   ```

3. Reboot your device:
   ```bash
   fastboot reboot
   ```

### Option 2: Using Recovery (recommended for most users)

1. Boot your device into recovery mode:
   - Power off your device
   - Press and hold Volume Up + Power buttons until the recovery screen appears

2. Select "Apply update from ADB" or "Apply update from SD card" depending on how you want to transfer the file

3. If using ADB, run:
   ```bash
   adb sideload output/NetHunter-gts7fe-flashable.zip
   ```
   
   If using SD card, transfer the ZIP to your SD card and select it in the recovery menu

4. Reboot your device after the installation completes

## Troubleshooting

### Boot Loop Issues

If your device gets stuck in a boot loop after flashing:

1. Boot back into recovery mode
2. Choose "Apply update from ADB"
3. Flash the stock LineageOS boot image or ROM to restore functionality

### Kernel Features Not Working

If NetHunter features are not working properly:

1. Check kernel logs with `adb shell dmesg | grep -i nethunter`
2. Verify that all required modules are enabled in the kernel config
3. Some features may require additional configuration in the NetHunter app

## Advanced: Custom Boot Image Modifications

For advanced users who want to make specific modifications to the boot image:

### Custom Ramdisk Modifications

If you need to modify the ramdisk (init scripts, etc.):

1. Extract the boot image:
   ```bash
   mkdir boot_extract
   cd boot_extract
   ../tools/magiskboot unpack /path/to/boot.img
   ```

2. Make your modifications to the ramdisk files

3. Repack the boot image:
   ```bash
   ../tools/magiskboot repack boot.img new-boot.img
   ```

### Custom Kernel Command Line

To modify the kernel command line parameters:

1. Extract the boot image as shown above
2. Edit the cmdline file
3. Repack with your changes

## Notes for Samsung Devices

Samsung devices have some specific considerations:

1. Some Samsung devices use a custom header for boot images. The script should handle this automatically.
2. If you're using a newer device with Samsung-specific protection (KNOX), flashing custom kernels may trip security features.
3. Always ensure your device is the correct model (SM-T733) before flashing any images.

## Support and Resources

If you encounter issues or need assistance:

1. Check the NetHunter documentation for device-specific guides
2. Join the NetHunter community forums or chat
3. Report issues on the NetHunter GitHub repository