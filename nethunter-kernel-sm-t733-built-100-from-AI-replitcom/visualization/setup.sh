#!/bin/bash
#
# NetHunter Packet Visualization - Dependency Installation Script
# For Samsung Galaxy Tab S7 FE running Kali NetHunter
#

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== NetHunter Packet Visualization - Dependency Installation =====${NC}"
echo -e "${BLUE}This script will install all required dependencies for the packet visualization tools${NC}"
echo -e "${BLUE}Designed for Samsung Galaxy Tab S7 FE running Kali NetHunter${NC}"
echo ""

# Check if we're running on a NetHunter system
if ! command -v apt-get &> /dev/null; then
    echo -e "${RED}Error: This script is designed to run on a Debian-based system (Kali NetHunter).${NC}"
    echo -e "${RED}Please run this on your NetHunter device.${NC}"
    exit 1
fi

# Check if we have root access (needed for package installation)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}This script requires root privileges to install packages.${NC}"
    echo -e "${YELLOW}Please run with sudo or as root.${NC}"
    exit 1
fi

# Ensure package lists are up to date
echo -e "${GREEN}Updating package lists...${NC}"
apt-get update || {
    echo -e "${RED}Failed to update package lists. Please check your internet connection.${NC}"
    exit 1
}

# Install required system dependencies
echo -e "${GREEN}Installing system dependencies...${NC}"
apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-tk \
    tcpdump \
    tshark \
    libpcap-dev || {
    echo -e "${RED}Failed to install system dependencies.${NC}"
    exit 1
}

# Install Python packages
echo -e "${GREEN}Installing Python packages for visualization...${NC}"
pip3 install --upgrade pip
pip3 install \
    matplotlib \
    pandas \
    numpy \
    scapy \
    pyshark \
    dpkt \
    networkx \
    pillow || {
    echo -e "${RED}Failed to install Python packages.${NC}"
    echo -e "${YELLOW}Some visualizations may not work properly.${NC}"
}

# Make the main script executable
chmod +x "$(dirname "$0")/nethunter_packet_visualizer.py"

# Create a desktop shortcut
DESKTOP_FILE="/usr/share/applications/nethunter-packet-visualizer.desktop"
echo -e "${GREEN}Creating desktop shortcut...${NC}"

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=NetHunter Packet Visualizer
Comment=Visualize network packet captures for security analysis
Exec=python3 $(dirname "$0")/nethunter_packet_visualizer.py
Icon=/usr/share/icons/hicolor/scalable/apps/kali-menu.svg
Terminal=false
Categories=Network;Security;
EOF

# Create a symbolic link in the bin directory for command line access
ln -sf "$(dirname "$0")/nethunter_packet_visualizer.py" /usr/local/bin/nethunter-visualizer

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo -e "${BLUE}You can now run the packet visualizer using:${NC}"
echo -e "  - Command: ${YELLOW}nethunter-visualizer${NC}"
echo -e "  - Or find it in your application menu as: ${YELLOW}NetHunter Packet Visualizer${NC}"
echo ""
echo -e "${BLUE}Example usage:${NC}"
echo -e "  ${YELLOW}nethunter-visualizer --pcap /path/to/capture.pcap${NC}"
echo ""