#!/bin/bash
#
# NetHunter Boot Image Creator for Samsung Galaxy Tab S7 FE (SM-T733)
# This script creates a flashable boot.img from the compiled kernel
#

# Set colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Set paths and variables
SCRIPTDIR="$(dirname "$(readlink -f "$0")")"
BASEDIR="$(dirname "$SCRIPTDIR")"
KERNELDIR="$BASEDIR/kernel"
OUTPUTDIR="$BASEDIR/output"
CONFIG_FILE="$BASEDIR/kernel_config.ini"
TMPDIR="$BASEDIR/tmp"
MAGISKBOOT="$BASEDIR/tools/magiskboot"
WORK_DIR="$TMPDIR/boot_img"

# Read settings from config file
DEVICE=$(grep "device=" ${CONFIG_FILE} | cut -d '=' -f2)
CODENAME=$(grep "codename=" ${CONFIG_FILE} | cut -d '=' -f2)
KERNEL_NAME=$(grep "kernel_name=" ${CONFIG_FILE} | cut -d '=' -f2)
LINEAGE_BRANCH=$(grep "lineage_branch=" ${CONFIG_FILE} | cut -d '=' -f2)

# Set default values if not found
DEVICE=${DEVICE:-"Samsung Galaxy Tab S7 FE"}
CODENAME=${CODENAME:-"gts7fe"}
KERNEL_NAME=${KERNEL_NAME:-"NetHunter-${CODENAME}"}
LINEAGE_BRANCH=${LINEAGE_BRANCH:-"lineage-19.1"}

# Function to display usage
function show_usage() {
    echo -e "Usage: $0 [OPTIONS]"
    echo -e "Options:"
    echo -e "  -s, --stock BOOT_IMG_PATH   Path to stock boot.img to use as base"
    echo -e "  -o, --output PATH           Output directory (default: $OUTPUTDIR)"
    echo -e "  -h, --help                  Show this help message"
    echo -e "\nExample:"
    echo -e "  $0 --stock /path/to/stock_boot.img"
}

# Parse command line arguments
STOCK_BOOT=""
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -s|--stock)
            STOCK_BOOT="$2"
            shift
            shift
            ;;
        -o|--output)
            OUTPUTDIR="$2"
            shift
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Check if magiskboot exists, download if not
function check_magiskboot() {
    if [ ! -f "$MAGISKBOOT" ]; then
        echo -e "${YELLOW}Downloading Magiskboot tool...${NC}"
        mkdir -p "$(dirname "$MAGISKBOOT")"
        wget -q "https://github.com/topjohnwu/Magisk/releases/download/v26.1/Magisk-v26.1.apk" -O "$TMPDIR/magisk.zip"
        unzip -j "$TMPDIR/magisk.zip" "lib/armeabi-v7a/libmagiskboot.so" -d "$TMPDIR"
        mv "$TMPDIR/libmagiskboot.so" "$MAGISKBOOT"
        chmod +x "$MAGISKBOOT"
        rm -f "$TMPDIR/magisk.zip"
    fi
}

# Function to check for required tools
function check_requirements() {
    echo -e "${BLUE}Checking requirements...${NC}"

    # Check for kernel Image
    if [ ! -f "${OUTPUTDIR}/Image.gz-dtb" ]; then
        echo -e "${RED}Error: Kernel image not found at ${OUTPUTDIR}/Image.gz-dtb${NC}"
        echo -e "${YELLOW}Please build the kernel first using build_kernel.sh${NC}"
        exit 1
    fi

    # Check for stock boot image
    if [ -z "$STOCK_BOOT" ]; then
        echo -e "${RED}Error: No stock boot.img provided${NC}"
        echo -e "${YELLOW}Please provide a stock boot.img using the --stock option${NC}"
        show_usage
        exit 1
    fi

    if [ ! -f "$STOCK_BOOT" ]; then
        echo -e "${RED}Error: Stock boot image not found at $STOCK_BOOT${NC}"
        exit 1
    fi

    # Check for required tools
    for cmd in mkbootimg mkfs.ext4 dd unzip; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}Error: Required command '$cmd' not found.${NC}"
            echo -e "${YELLOW}Please install the package containing this command.${NC}"
            exit 1
        fi
    fi

    # Check magiskboot
    check_magiskboot

    echo -e "${GREEN}All requirements met.${NC}"
}

# Function to extract stock boot image
function extract_stock_boot() {
    echo -e "${BLUE}Extracting stock boot image...${NC}"
    
    # Create temporary directory
    mkdir -p "$WORK_DIR"
    
    # Copy stock boot image to work directory
    cp "$STOCK_BOOT" "$WORK_DIR/boot.img"
    
    # Change to work directory
    pushd "$WORK_DIR" > /dev/null
    
    # Extract boot image using magiskboot
    "$MAGISKBOOT" unpack -h boot.img
    
    if [ ! -f "$WORK_DIR/kernel" ]; then
        echo -e "${RED}Error: Failed to extract kernel from boot image${NC}"
        popd > /dev/null
        exit 1
    fi
    
    echo -e "${GREEN}Stock boot image extracted successfully.${NC}"
    popd > /dev/null
}

# Function to create new boot image
function create_boot_image() {
    echo -e "${BLUE}Creating new boot image...${NC}"
    
    # Replace stock kernel with NetHunter kernel
    cp "${OUTPUTDIR}/Image.gz-dtb" "$WORK_DIR/kernel"
    
    # Change to work directory
    pushd "$WORK_DIR" > /dev/null
    
    # Repack boot image
    "$MAGISKBOOT" repack boot.img new-boot.img
    
    if [ ! -f "$WORK_DIR/new-boot.img" ]; then
        echo -e "${RED}Error: Failed to create new boot image${NC}"
        popd > /dev/null
        exit 1
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "${OUTPUTDIR}"
    
    # Copy new boot image to output directory
    cp "$WORK_DIR/new-boot.img" "${OUTPUTDIR}/${KERNEL_NAME}-boot.img"
    
    echo -e "${GREEN}New boot image created successfully.${NC}"
    echo -e "${GREEN}Boot image saved to: ${OUTPUTDIR}/${KERNEL_NAME}-boot.img${NC}"
    popd > /dev/null
}

# Function to create flashable zip
function create_flashable_zip() {
    echo -e "${BLUE}Creating flashable zip...${NC}"
    
    # Create a temporary directory for the flashable zip
    local FLASHABLE_DIR="${TMPDIR}/flashable"
    mkdir -p "${FLASHABLE_DIR}/META-INF/com/google/android"
    
    # Create updater-script
    cat > "${FLASHABLE_DIR}/META-INF/com/google/android/updater-script" << EOF
#!
# NetHunter Kernel Installer for ${DEVICE} (${CODENAME})
# 
# - Kernel: ${KERNEL_NAME} (LineageOS ${LINEAGE_BRANCH})
# - Date: $(date +"%Y-%m-%d")
# - Built with enhanced security testing features
#

# Display installation message
ui_print("Installing ${KERNEL_NAME} Kernel for ${DEVICE}");
ui_print("Based on LineageOS ${LINEAGE_BRANCH}");
ui_print("With NetHunter security testing features");

# Mount partitions
ui_print("Mounting partitions...");
package_extract_file("boot.img", "/dev/block/bootdevice/by-name/boot");

# Finished
ui_print(" ");
ui_print("Installation complete!");
ui_print(" ");
ui_print("Features enabled:");
ui_print("- HID/BadUSB support");
ui_print("- WiFi monitor mode and packet injection");
ui_print("- USB gadget support");
ui_print("- Battery optimization");
ui_print("- Tool stability enhancements");
ui_print(" ");
ui_print("Reboot to use your new NetHunter kernel!");
EOF
    
    # Create update-binary
    cat > "${FLASHABLE_DIR}/META-INF/com/google/android/update-binary" << 'EOF'
#!/sbin/sh
# NetHunter Kernel Flasher
#

OUTFD=/proc/self/fd/$2
ZIPFILE="$3"

ui_print() {
  echo -e "ui_print $1\nui_print" > $OUTFD
}

package_extract_file() {
  unzip -p "$ZIPFILE" "$1" > "$2"
  return $?
}

umask 022

ui_print " ";
ui_print "***********************************";
ui_print "* NetHunter Kernel Installation   *";
ui_print "***********************************";
ui_print " ";

# Extract and install boot.img
ui_print "Extracting boot image...";
package_extract_file "boot.img" "/dev/block/bootdevice/by-name/boot" || {
  ui_print "Error: Failed to flash boot partition!";
  exit 1;
}

# Set permissions (not always necessary in recovery)
chmod 644 /dev/block/bootdevice/by-name/boot

ui_print " ";
ui_print "NetHunter kernel flashed successfully!";
ui_print " ";
ui_print "Reboot your device to use the new kernel.";
ui_print " ";

exit 0
EOF
    
    # Make the update-binary executable
    chmod +x "${FLASHABLE_DIR}/META-INF/com/google/android/update-binary"
    
    # Copy boot image to the flashable zip directory
    cp "${OUTPUTDIR}/${KERNEL_NAME}-boot.img" "${FLASHABLE_DIR}/boot.img"
    
    # Create a README file
    cat > "${FLASHABLE_DIR}/README.txt" << EOF
NetHunter Kernel for ${DEVICE} (${CODENAME})
=============================================

This package contains a custom kernel with NetHunter security testing features:

- Device: ${DEVICE} (${CODENAME})
- Kernel: ${KERNEL_NAME}
- Base: LineageOS ${LINEAGE_BRANCH}
- Date: $(date +"%Y-%m-%d")

Features:
- HID/BadUSB support
- WiFi monitor mode and packet injection
- USB gadget support
- Battery optimization
- Tool stability enhancements

Installation:
1. Boot into recovery mode
2. Flash this zip file
3. Reboot your device

Note: This kernel is meant to be used with LineageOS ${LINEAGE_BRANCH} or compatible ROMs.
EOF
    
    # Create the flashable zip
    pushd "${FLASHABLE_DIR}" > /dev/null
    zip -r "${OUTPUTDIR}/${KERNEL_NAME}-flashable.zip" *
    popd > /dev/null
    
    echo -e "${GREEN}Flashable zip created successfully.${NC}"
    echo -e "${GREEN}Flashable zip saved to: ${OUTPUTDIR}/${KERNEL_NAME}-flashable.zip${NC}"
}

# Function to clean up
function cleanup() {
    echo -e "${BLUE}Cleaning up...${NC}"
    rm -rf "${WORK_DIR}"
    rm -rf "${TMPDIR}/flashable"
    echo -e "${GREEN}Cleanup complete.${NC}"
}

# Main execution
function main() {
    echo -e "${BLUE}===== NetHunter Boot Image Creator =====${NC}"
    echo -e "${GREEN}Device:${NC} ${DEVICE} (${CODENAME})"
    echo -e "${GREEN}Kernel:${NC} ${KERNEL_NAME}"
    echo -e "${GREEN}LineageOS Branch:${NC} ${LINEAGE_BRANCH}"
    
    # Create temporary directory
    mkdir -p "${TMPDIR}"
    
    # Check requirements
    check_requirements
    
    # Extract stock boot image
    extract_stock_boot
    
    # Create new boot image
    create_boot_image
    
    # Create flashable zip
    create_flashable_zip
    
    # Clean up
    cleanup
    
    echo -e "\n${GREEN}Boot image creation complete!${NC}"
    echo -e "${BLUE}Boot image:${NC} ${OUTPUTDIR}/${KERNEL_NAME}-boot.img"
    echo -e "${BLUE}Flashable zip:${NC} ${OUTPUTDIR}/${KERNEL_NAME}-flashable.zip"
    echo -e "\n${YELLOW}To flash this kernel:${NC}"
    echo -e "1. Boot your device into recovery mode"
    echo -e "2. Flash the ${KERNEL_NAME}-flashable.zip file"
    echo -e "3. Reboot your device"
    echo -e "\n${YELLOW}Alternatively, you can flash directly using Fastboot:${NC}"
    echo -e "fastboot flash boot ${OUTPUTDIR}/${KERNEL_NAME}-boot.img"
}

# Run the main function
main