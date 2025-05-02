#!/bin/bash
# NetHunter Kernel Builder Script for Samsung Galaxy Tab S7 FE (SM-T733)
# This script automates the process of building a custom NetHunter kernel

set -e

# Color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directory setup
BASEDIR=$(pwd)
KERNELDIR="${BASEDIR}/kernel"
OUTPUTDIR="${BASEDIR}/output"
PATCHDIR="${BASEDIR}/patches"
CONFIG_FILE="${BASEDIR}/kernel_config.ini"

# Parse configuration
KERNEL_NAME=$(grep "name=" ${CONFIG_FILE} | cut -d '=' -f2)
DEVICE=$(grep "device=" ${CONFIG_FILE} | cut -d '=' -f2)
CODENAME=$(grep "codename=" ${CONFIG_FILE} | cut -d '=' -f2)
LINEAGE_BRANCH=$(grep "lineage_branch=" ${CONFIG_FILE} | cut -d '=' -f2)
KERNEL_SOURCE=$(grep "kernel_source=" ${CONFIG_FILE} | cut -d '=' -f2)
CLONE_DEPTH=$(grep "clone_depth=" ${CONFIG_FILE} | cut -d '=' -f2)
DEFCONFIG=$(grep "defconfig=" ${CONFIG_FILE} | cut -d '=' -f2)

# NetHunter features
ADD_HID=$(grep "add_hid=" ${CONFIG_FILE} | cut -d '=' -f2)
ADD_WIFI_INJECTION=$(grep "add_wifi_injection=" ${CONFIG_FILE} | cut -d '=' -f2)
ADD_USB_GADGETS=$(grep "add_usb_gadgets=" ${CONFIG_FILE} | cut -d '=' -f2)
ADD_BATTERY_OPTIMIZATION=$(grep "add_battery_optimization=" ${CONFIG_FILE} | cut -d '=' -f2)
ADD_TOOL_STABILITY=$(grep "add_tool_stability=" ${CONFIG_FILE} | cut -d '=' -f2)
ADD_ALL_FEATURES=$(grep "add_all_features=" ${CONFIG_FILE} | cut -d '=' -f2)

# Print build information
echo -e "${BLUE}===== NetHunter Kernel Build Script =====${NC}"
echo -e "${GREEN}Building kernel for:${NC} ${DEVICE} (${CODENAME})"
echo -e "${GREEN}Kernel name:${NC} ${KERNEL_NAME}"
echo -e "${GREEN}LineageOS branch:${NC} ${LINEAGE_BRANCH}"
echo -e "${GREEN}Kernel defconfig:${NC} ${DEFCONFIG}"

# Function to clone kernel source
clone_kernel_source() {
    echo -e "\n${YELLOW}Cloning kernel source...${NC}"
    
    if [ ! -d "${KERNELDIR}" ]; then
        echo -e "${BLUE}Cloning from:${NC} ${KERNEL_SOURCE}"
        if [ "${CLONE_DEPTH}" -gt 0 ]; then
            git clone --depth=${CLONE_DEPTH} ${KERNEL_SOURCE} ${KERNELDIR}
        else
            git clone ${KERNEL_SOURCE} ${KERNELDIR}
        fi
        
        cd ${KERNELDIR}
        
        # Check if we need to checkout a specific branch
        if [ -n "${LINEAGE_BRANCH}" ]; then
            git checkout ${LINEAGE_BRANCH} || echo -e "${RED}Branch ${LINEAGE_BRANCH} not found, using default branch.${NC}"
        fi
    else
        echo -e "${GREEN}Kernel source already cloned. Skipping...${NC}"
        cd ${KERNELDIR}
        git pull
    fi
}

# Function to apply NetHunter patches
apply_patches() {
    echo -e "\n${YELLOW}Applying NetHunter patches...${NC}"
    cd ${KERNELDIR}
    
    # Apply HID support patch
    if [ "${ADD_HID}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo -e "${BLUE}Applying HID support patch...${NC}"
        git apply ${PATCHDIR}/hid_support.patch || echo -e "${RED}Failed to apply HID patch${NC}"
    fi
    
    # Apply WiFi injection patch
    if [ "${ADD_WIFI_INJECTION}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo -e "${BLUE}Applying WiFi injection patch...${NC}"
        git apply ${PATCHDIR}/wifi_injection.patch || echo -e "${RED}Failed to apply WiFi injection patch${NC}"
    fi
    
    # Apply USB gadgets patch
    if [ "${ADD_USB_GADGETS}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo -e "${BLUE}Applying USB gadgets patch...${NC}"
        git apply ${PATCHDIR}/usb_gadget.patch || echo -e "${RED}Failed to apply USB gadget patch${NC}"
    fi
    
    # Apply battery optimization patch
    if [ "${ADD_BATTERY_OPTIMIZATION}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo -e "${BLUE}Applying battery optimization patch...${NC}"
        git apply ${PATCHDIR}/battery_optimization.patch || echo -e "${RED}Failed to apply battery optimization patch${NC}"
    fi
    
    # Apply tool stability patch
    if [ "${ADD_TOOL_STABILITY}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo -e "${BLUE}Applying penetration testing tool stability patch...${NC}"
        git apply ${PATCHDIR}/tool_stability.patch || echo -e "${RED}Failed to apply tool stability patch${NC}"
    fi
}

# Function to modify kernel config
modify_kernel_config() {
    echo -e "\n${YELLOW}Modifying kernel configuration...${NC}"
    cd ${KERNELDIR}
    
    # Make sure the defconfig exists
    if [ ! -f "arch/arm64/configs/${DEFCONFIG}" ]; then
        echo -e "${RED}Error: Defconfig not found at arch/arm64/configs/${DEFCONFIG}${NC}"
        exit 1
    fi
    
    # Create a working copy of the defconfig
    cp arch/arm64/configs/${DEFCONFIG} arch/arm64/configs/${DEFCONFIG}.nethunter
    
    # Enable NetHunter-specific kernel options
    if [ "${ADD_HID}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo "CONFIG_USB_CONFIGFS_F_HID=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
    fi
    
    if [ "${ADD_WIFI_INJECTION}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo "CONFIG_CFG80211_DEBUGFS=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CFG80211_INTERNAL_REGDB=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CFG80211_WEXT=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_MAC80211=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_MAC80211_HAS_RC=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_MAC80211_RC_MINSTREL=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_MAC80211_RC_DEFAULT_MINSTREL=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
    fi
    
    if [ "${ADD_USB_GADGETS}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo "CONFIG_USB_GADGET=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_CONFIGFS=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_CONFIGFS_SERIAL=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_CONFIGFS_ACM=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_CONFIGFS_OBEX=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_CONFIGFS_NCM=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_CONFIGFS_ECM=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_CONFIGFS_RNDIS=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_CONFIGFS_MASS_STORAGE=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
    fi
    
    # Enable battery optimization features
    if [ "${ADD_BATTERY_OPTIMIZATION}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo -e "${BLUE}Adding battery optimization config...${NC}"
        # CPU Frequency scaling options
        echo "CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CPU_FREQ_GOV_POWERSAVE=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        
        # CPU Idle options
        echo "CONFIG_CPU_IDLE=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CPU_IDLE_GOV_LADDER=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CPU_IDLE_GOV_MENU=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        
        # Power management options
        echo "CONFIG_PM_AUTOSLEEP=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_PM_WAKELOCKS=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_PM_DEBUG=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_SUSPEND_TIME=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        
        # NetHunter specific power management
        echo "CONFIG_NETHUNTER_POWER_MANAGEMENT=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
    fi
    
    # Enable tool stability features
    if [ "${ADD_TOOL_STABILITY}" = "true" ] || [ "${ADD_ALL_FEATURES}" = "true" ]; then
        echo -e "${BLUE}Adding penetration testing tool stability config...${NC}"
        
        # Memory management for stability
        echo "CONFIG_COMPAT_BRK=n" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CLEANCACHE=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_FRONTSWAP=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CMA=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_ZSMALLOC=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_PROCESS_RECLAIM=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        
        # OOM killer adjustments
        echo "CONFIG_HAVE_MEMBLOCK=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_FORCE_MAX_ZONEORDER=11" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        
        # Resource limiting for stability
        echo "CONFIG_RESOURCE_COUNTERS=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_RT_GROUP_SCHED=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_SCHED_AUTOGROUP=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        
        # USB stability for external adapters
        echo "CONFIG_USB_OTG=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_EHCI_HCD=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_ACM=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_WDM=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_USB_RTL8152=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        
        # Enhanced wireless stability
        echo "CONFIG_MAC80211_DEBUGFS=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_RFKILL=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_CFG80211_DEBUGFS=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_MAC80211_MESH=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        
        # Security and process management
        echo "CONFIG_SECURITY_YAMA=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_MAGIC_SYSRQ=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_DETECT_HUNG_TASK=y" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=120" >> arch/arm64/configs/${DEFCONFIG}.nethunter
        echo "CONFIG_BOOTPARAM_HUNG_TASK_PANIC=n" >> arch/arm64/configs/${DEFCONFIG}.nethunter
    fi
    
    # Use the modified config
    DEFCONFIG="${DEFCONFIG}.nethunter"
}

# Function to build the kernel
build_kernel() {
    echo -e "\n${YELLOW}Building NetHunter kernel...${NC}"
    cd ${KERNELDIR}
    
    # Setup compiler environment
    export ARCH=arm64
    export SUBARCH=arm64
    
    # Setup build options
    MAKE_OPTS="-j$(nproc --all) O=out ARCH=arm64"
    
    # Prepare build environment
    mkdir -p out
    
    # Prepare kernel configuration
    echo -e "${BLUE}Preparing kernel configuration...${NC}"
    make ${MAKE_OPTS} ${DEFCONFIG}
    
    # Build the kernel
    echo -e "${BLUE}Building kernel...${NC}"
    make ${MAKE_OPTS}
    
    # Check if kernel build was successful
    if [ -f "out/arch/arm64/boot/Image" ]; then
        echo -e "${GREEN}Kernel build successful!${NC}"
        
        # Create output directory if it doesn't exist
        mkdir -p ${OUTPUTDIR}
        
        # Copy kernel image to output directory
        cp out/arch/arm64/boot/Image ${OUTPUTDIR}/
        
        # Pack the kernel if dtb exists
        if [ -d "out/arch/arm64/boot/dts" ]; then
            echo -e "${BLUE}Packing kernel with DTB...${NC}"
            find out/arch/arm64/boot/dts -name "*.dtb" -exec cat {} \; > ${OUTPUTDIR}/dtb
            cat ${OUTPUTDIR}/Image ${OUTPUTDIR}/dtb > ${OUTPUTDIR}/Image.gz-dtb
        fi
        
        echo -e "${GREEN}Kernel files saved to ${OUTPUTDIR}${NC}"
    else
        echo -e "${RED}Kernel build failed!${NC}"
        exit 1
    fi
}

# Main execution
main() {
    # Create output directory
    mkdir -p ${OUTPUTDIR}
    
    # Clone kernel source
    clone_kernel_source
    
    # Apply NetHunter patches
    apply_patches
    
    # Modify kernel config
    modify_kernel_config
    
    # Build the kernel
    build_kernel
    
    echo -e "\n${GREEN}NetHunter kernel build complete!${NC}"
    echo -e "${BLUE}Kernel can be found at:${NC} ${OUTPUTDIR}/Image.gz-dtb"
}

# Run the main function
main