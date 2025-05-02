# NetHunter Packet Visualization Guide

This guide explains how to use the network packet visualization tools included with your custom NetHunter kernel for the Samsung Galaxy Tab S7 FE.

## Overview

The packet visualization toolset provides comprehensive analysis and graphical representation of network traffic captured during security assessments. These tools help you better understand network communications, identify patterns, and discover potential security issues.

## Available Tools

The NetHunter packet visualization toolkit includes three main components:

1. **GUI Packet Visualizer** - A graphical application with interactive charts and graphs for detailed packet analysis
2. **CLI Packet Visualizer** - A lightweight command-line tool for quick ASCII-based visualizations
3. **PCAP to HTML Converter** - A tool to generate standalone HTML reports from packet captures

## Installation

Before using these tools, you need to install the required dependencies:

```bash
# Navigate to the visualization directory
cd /path/to/nethunter/visualization

# Make the setup script executable
chmod +x setup.sh

# Run the setup script with root privileges
sudo ./setup.sh
```

This will install all necessary system dependencies and Python packages required for packet visualization.

## GUI Packet Visualizer

The GUI Packet Visualizer provides a rich graphical interface with interactive charts and visualizations.

### Features

- Protocol distribution charts
- Traffic volume analysis
- Endpoint connection mapping
- Top talkers visualization
- Packet size distribution
- Interactive connection graphs

### Usage

```bash
# Basic usage
python3 nethunter_packet_visualizer.py

# Open a specific PCAP file on startup
python3 nethunter_packet_visualizer.py --pcap /path/to/capture.pcap
```

### Interface Guide

1. **Open PCAP** - Click to load a packet capture file
2. **Protocol Distribution** - Shows the breakdown of protocols in the capture
3. **Packet Sizes** - Visualizes packet sizes over time
4. **Traffic Volume** - Displays traffic volume over time
5. **Connection Graph** - Shows a network graph of connections between hosts
6. **Top Talkers** - Identifies the most active IP addresses
7. **Transport Protocols** - Shows the distribution of transport layer protocols

## CLI Packet Visualizer

The CLI Packet Visualizer is a lightweight command-line tool for quick analysis with ASCII-based visualizations. It's ideal for remote terminals or low-resource environments.

### Features

- Protocol distribution histograms
- Time-series traffic volume graphs
- Top talkers visualization
- Connection maps
- Packet size distribution

### Usage

```bash
# Basic usage
python3 nethunter_cli_visualizer.py /path/to/capture.pcap

# Customize graph dimensions
python3 nethunter_cli_visualizer.py /path/to/capture.pcap --width 100 --height 30

# Adjust histogram bins
python3 nethunter_cli_visualizer.py /path/to/capture.pcap --bins 15

# Show more top talkers
python3 nethunter_cli_visualizer.py /path/to/capture.pcap --top 20
```

## PCAP to HTML Converter

The PCAP to HTML Converter generates comprehensive, standalone HTML reports from packet captures. These reports can be viewed in any web browser and are ideal for sharing analysis results.

### Features

- Interactive charts with Chart.js
- Connection graphs with D3.js
- HTTP request/response analysis
- Packet tables with search capability
- Mobile-friendly responsive design

### Usage

```bash
# Basic usage
python3 nethunter_pcap_to_html.py /path/to/capture.pcap

# Specify output file
python3 nethunter_pcap_to_html.py /path/to/capture.pcap -o report.html
```

The generated HTML file can be opened in any modern web browser and does not require an internet connection (all dependencies are embedded).

## Capturing Network Traffic

To visualize network traffic, you first need to capture it. Here are some common methods:

### Using tcpdump

```bash
# Capture traffic on WiFi interface for 60 seconds
sudo tcpdump -i wlan0 -w capture.pcap -G 60 -W 1

# Capture HTTP traffic only
sudo tcpdump -i wlan0 -w http_capture.pcap port 80

# Capture traffic to/from a specific host
sudo tcpdump -i wlan0 -w target_capture.pcap host 192.168.1.10
```

### Using Wireshark

If you have Wireshark installed on your NetHunter device:

1. Open Wireshark
2. Select the network interface (e.g., wlan0, eth0)
3. Click the "Start Capture" button
4. Perform the network activity you want to analyze
5. Click the "Stop Capture" button
6. Save the capture (File > Save As) as a .pcap file

### Using WiFi Monitor Mode (requires kernel support)

```bash
# Set WiFi adapter to monitor mode
sudo airmon-ng start wlan0

# Capture packets in monitor mode
sudo tcpdump -i wlan0mon -w monitor_capture.pcap
```

## Tips for Effective Analysis

1. **Focus on Specific Traffic** - Use capture filters to focus on relevant traffic and avoid overwhelming the visualization tools
2. **Look for Patterns** - Unusual spikes in traffic or unexpected connections might indicate security issues
3. **Identify Top Talkers** - High-volume traffic from unexpected sources could signal data exfiltration or malware
4. **HTTP Analysis** - Examine HTTP requests and responses for suspicious patterns or unexpected data
5. **Save Reports** - Generate HTML reports for important captures to maintain evidence for security assessments

## Troubleshooting

### Missing Dependencies

If you encounter missing dependency errors:

```bash
# Re-run the setup script
sudo ./setup.sh

# Install a specific missing package
pip3 install <package_name>
```

### Performance Issues

For large PCAP files:

1. Use the CLI visualizer for initial analysis
2. Filter the capture to focus on relevant traffic:

```bash
# Extract a subset of packets from a large capture
tcpdump -r large_capture.pcap -w smaller_capture.pcap 'host 192.168.1.1'
```

### No WiFi Monitor Mode

If you cannot enable monitor mode, verify that your kernel has the required patches:

```bash
# Check if monitor mode is supported
iw list | grep -A 10 "Supported interface modes" | grep "monitor"
```

## Advanced Use Cases

### Security Assessment Reporting

Generate HTML reports for client deliverables or team communication:

```bash
# Create a comprehensive report
python3 nethunter_pcap_to_html.py assessment.pcap -o client_report.html
```

### Live Traffic Analysis

Set up a script to continuously capture and analyze traffic:

```bash
#!/bin/bash
while true; do
    # Capture for 60 seconds
    sudo tcpdump -i wlan0 -w temp.pcap -G 60 -W 1
    
    # Analyze the capture
    python3 nethunter_cli_visualizer.py temp.pcap
    
    # Ask to continue
    read -p "Continue monitoring? (y/n) " answer
    if [ "$answer" != "y" ]; then
        break
    fi
done
```

### Integration with Other Tools

Combine with other NetHunter tools:

```bash
# Capture traffic during a Metasploit session
sudo tcpdump -i wlan0 -w metasploit_session.pcap &
msfconsole
# (perform testing)
killall tcpdump

# Analyze the capture
python3 nethunter_packet_visualizer.py --pcap metasploit_session.pcap
```

## Conclusion

The NetHunter packet visualization toolkit provides powerful capabilities for analyzing network traffic during security assessments. By understanding the patterns and characteristics of network communications, you can more effectively identify vulnerabilities, detect malicious behavior, and document your findings.

For any issues or feature requests, please refer to the NetHunter documentation or community forums.

---

Created for Samsung Galaxy Tab S7 FE (SM-T733) running Kali NetHunter