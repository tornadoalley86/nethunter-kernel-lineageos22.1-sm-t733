#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetHunter CLI Packet Visualizer

A command-line tool for visualizing network packet captures with ASCII art
and terminal graphics, ideal for remote terminals and low-resource environments.

Features:
- Protocol distribution histograms
- Time-series traffic volume graphs
- Top talkers visualization
- Connection maps
- Packet size distribution
"""

import os
import sys
import time
import argparse
import logging
from datetime import datetime

# Import pcap parsing libraries with error handling
try:
    from scapy.all import rdpcap, PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. PCAP parsing may not work properly.")
    print("Install Scapy with: pip install scapy")

# Terminal colors
class TermColors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("NetHunterCLIVisualizer")

class PacketParser:
    """Handle packet parsing from different capture formats"""
    
    def __init__(self):
        self.packets = []
        self.file_path = None
        self.packet_count = 0
        self.start_time = None
        self.end_time = None
        self.duration = 0
        
    def load_pcap(self, file_path):
        """Load and parse a pcap file"""
        self.file_path = file_path
        self.packets = []
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not available. Cannot parse PCAP file.")
            return False
            
        try:
            # Try to read file with scapy
            logger.info(f"Loading PCAP file: {file_path}")
            packet_reader = PcapReader(file_path)
            
            # Process packets into structured data
            for i, packet in enumerate(packet_reader):
                try:
                    packet_data = self._parse_packet(packet)
                    self.packets.append(packet_data)
                except Exception as e:
                    logger.warning(f"Error parsing packet #{i}: {str(e)}")
                    continue
                    
            self.packet_count = len(self.packets)
            
            # Calculate capture duration
            if self.packets:
                self.start_time = min(p['timestamp'] for p in self.packets)
                self.end_time = max(p['timestamp'] for p in self.packets)
                self.duration = self.end_time - self.start_time
            
            logger.info(f"Loaded {self.packet_count} packets from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load PCAP file: {str(e)}")
            return False
    
    def _parse_packet(self, packet):
        """Extract relevant fields from a packet"""
        # Initialize packet data dictionary
        packet_data = {
            'timestamp': float(packet.time),
            'datetime': datetime.fromtimestamp(float(packet.time)),
            'size': len(packet),
            'src': None,
            'dst': None,
            'protocol': None,
            'transport_protocol': None,
            'src_port': None,
            'dst_port': None,
            'ttl': None,
            'flags': None,
            'length': None
        }
        
        # Parse IP layer if present
        if packet.haslayer('IP'):
            packet_data['src'] = packet['IP'].src
            packet_data['dst'] = packet['IP'].dst
            packet_data['ttl'] = packet['IP'].ttl
            packet_data['length'] = packet['IP'].len
            
        # Determine transport protocol
        if packet.haslayer('TCP'):
            packet_data['transport_protocol'] = 'TCP'
            packet_data['src_port'] = packet['TCP'].sport
            packet_data['dst_port'] = packet['TCP'].dport
            packet_data['flags'] = packet['TCP'].flags
            
            # Try to determine application protocol
            if packet_data['dst_port'] == 80 or packet_data['src_port'] == 80:
                packet_data['protocol'] = 'HTTP'
            elif packet_data['dst_port'] == 443 or packet_data['src_port'] == 443:
                packet_data['protocol'] = 'HTTPS'
            else:
                packet_data['protocol'] = 'TCP'
                
        elif packet.haslayer('UDP'):
            packet_data['transport_protocol'] = 'UDP'
            packet_data['src_port'] = packet['UDP'].sport
            packet_data['dst_port'] = packet['UDP'].dport
            
            # Check for DNS
            if packet_data['dst_port'] == 53 or packet_data['src_port'] == 53:
                packet_data['protocol'] = 'DNS'
            else:
                packet_data['protocol'] = 'UDP'
                
        elif packet.haslayer('ICMP'):
            packet_data['protocol'] = 'ICMP'
            packet_data['transport_protocol'] = 'ICMP'
            
        return packet_data
    
    def get_protocol_distribution(self):
        """Get distribution of protocols in the capture"""
        protocols = {}
        
        for packet in self.packets:
            proto = packet['protocol']
            if proto:
                if proto in protocols:
                    protocols[proto] += 1
                else:
                    protocols[proto] = 1
                    
        return protocols
    
    def get_transport_protocol_distribution(self):
        """Get distribution of transport protocols"""
        transport_protocols = {}
        
        for packet in self.packets:
            proto = packet['transport_protocol']
            if proto:
                if proto in transport_protocols:
                    transport_protocols[proto] += 1
                else:
                    transport_protocols[proto] = 1
                    
        return transport_protocols
    
    def get_top_talkers(self, n=10):
        """Get the top n talking IP addresses"""
        talkers = {}
        
        for packet in self.packets:
            src = packet['src']
            if src:
                if src in talkers:
                    talkers[src] += 1
                else:
                    talkers[src] = 1
                    
        # Sort by count (descending) and take top n
        talkers = dict(sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:n])
        return talkers
    
    def get_traffic_volume_over_time(self, bins=20):
        """Get traffic volume over time, binned into intervals"""
        if not self.packets or self.duration == 0:
            return [], []
            
        # Determine bin size based on capture duration
        bin_size = self.duration / bins
        
        # Initialize bins
        bin_times = []
        bin_volumes = [0] * bins
        
        # Calculate bin start times
        for i in range(bins):
            bin_time = self.start_time + (i * bin_size)
            bin_times.append(bin_time)
            
        # Assign packets to bins
        for packet in self.packets:
            timestamp = packet['timestamp']
            size = packet['size']
            
            # Determine which bin this packet belongs to
            bin_index = min(int((timestamp - self.start_time) / bin_size), bins - 1)
            bin_volumes[bin_index] += size
            
        return bin_times, bin_volumes
    
    def get_packet_size_distribution(self, bins=10):
        """Get distribution of packet sizes"""
        if not self.packets:
            return [], []
            
        # Get all packet sizes
        sizes = [packet['size'] for packet in self.packets]
        
        # Determine bin edges
        min_size = min(sizes)
        max_size = max(sizes)
        bin_size = (max_size - min_size) / bins if max_size > min_size else 1
        
        # Initialize bins
        bin_edges = []
        bin_counts = [0] * bins
        
        # Calculate bin edges
        for i in range(bins):
            bin_edge = min_size + (i * bin_size)
            bin_edges.append(bin_edge)
            
        # Count packets in each bin
        for size in sizes:
            # Determine which bin this packet belongs to
            bin_index = min(int((size - min_size) / bin_size), bins - 1)
            bin_counts[bin_index] += 1
            
        return bin_edges, bin_counts
    
    def get_connections(self):
        """Get unique connections between hosts"""
        connections = set()
        
        for packet in self.packets:
            src = packet['src']
            dst = packet['dst']
            if src and dst:
                connections.add((src, dst))
                
        return list(connections)


class CLIVisualizer:
    """Generate ASCII visualizations for terminal"""
    
    def __init__(self, parser, width=80, height=20):
        self.parser = parser
        self.width = width
        self.height = height
        
        # Try to get terminal size
        try:
            term_size = os.get_terminal_size()
            self.width = term_size.columns
            self.height = term_size.lines - 5  # Leave room for headers/footers
        except (OSError, AttributeError):
            # Use defaults if terminal size can't be determined
            pass
    
    def horizontal_bar(self, value, max_value, width=None, fill_char='█', empty_char='░'):
        """Create a horizontal bar with given value and maximum"""
        if width is None:
            width = self.width - 30  # Leave room for labels
            
        # Calculate filled portion
        if max_value > 0:
            filled = int((value / max_value) * width)
        else:
            filled = 0
            
        # Create bar
        bar = fill_char * filled + empty_char * (width - filled)
        return bar
    
    def format_number(self, num):
        """Format number with thousands separator"""
        return f"{num:,}"
    
    def print_header(self, title):
        """Print a section header"""
        print()
        print(f"{TermColors.BOLD}{TermColors.HEADER}{'=' * self.width}{TermColors.ENDC}")
        print(f"{TermColors.BOLD}{TermColors.HEADER}{title.center(self.width)}{TermColors.ENDC}")
        print(f"{TermColors.BOLD}{TermColors.HEADER}{'=' * self.width}{TermColors.ENDC}")
        print()
    
    def print_capture_summary(self):
        """Print summary of the packet capture"""
        self.print_header("PACKET CAPTURE SUMMARY")
        
        # Get filename
        filename = os.path.basename(self.parser.file_path)
        
        # Format timestamps
        start_time = "N/A"
        end_time = "N/A"
        duration = "N/A"
        
        if self.parser.start_time:
            start_time = datetime.fromtimestamp(self.parser.start_time).strftime('%Y-%m-%d %H:%M:%S')
        if self.parser.end_time:
            end_time = datetime.fromtimestamp(self.parser.end_time).strftime('%Y-%m-%d %H:%M:%S')
        if self.parser.duration:
            duration = f"{self.parser.duration:.2f} seconds"
        
        # Print summary
        print(f"{TermColors.BOLD}File:{TermColors.ENDC} {filename}")
        print(f"{TermColors.BOLD}Packets:{TermColors.ENDC} {self.format_number(self.parser.packet_count)}")
        print(f"{TermColors.BOLD}Start Time:{TermColors.ENDC} {start_time}")
        print(f"{TermColors.BOLD}End Time:{TermColors.ENDC} {end_time}")
        print(f"{TermColors.BOLD}Duration:{TermColors.ENDC} {duration}")
        print()
    
    def print_protocol_distribution(self):
        """Print protocol distribution as horizontal bars"""
        protocols = self.parser.get_protocol_distribution()
        
        if not protocols:
            return
            
        self.print_header("PROTOCOL DISTRIBUTION")
        
        # Sort protocols by count (descending)
        sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
        
        # Get maximum count for scaling
        max_count = max(protocols.values()) if protocols else 0
        
        # Print each protocol
        for protocol, count in sorted_protocols:
            # Determine color based on protocol
            color = TermColors.BLUE  # Default color
            if protocol == 'TCP':
                color = TermColors.BLUE
            elif protocol == 'UDP':
                color = TermColors.RED
            elif protocol == 'ICMP':
                color = TermColors.GREEN
            elif protocol == 'DNS':
                color = TermColors.YELLOW
            elif protocol == 'HTTP':
                color = TermColors.CYAN
            elif protocol == 'HTTPS':
                color = TermColors.CYAN
                
            # Create bar
            bar = self.horizontal_bar(count, max_count)
            
            # Print protocol with count and bar
            print(f"{protocol.ljust(8)}: {self.format_number(count).rjust(7)} {color}{bar}{TermColors.ENDC}")
            
        print()
    
    def print_transport_protocol_distribution(self):
        """Print transport protocol distribution as horizontal bars"""
        transport_protocols = self.parser.get_transport_protocol_distribution()
        
        if not transport_protocols:
            return
            
        self.print_header("TRANSPORT PROTOCOL DISTRIBUTION")
        
        # Sort protocols by count (descending)
        sorted_protocols = sorted(transport_protocols.items(), key=lambda x: x[1], reverse=True)
        
        # Get maximum count for scaling
        max_count = max(transport_protocols.values()) if transport_protocols else 0
        
        # Print each protocol
        for protocol, count in sorted_protocols:
            # Determine color based on protocol
            color = TermColors.BLUE  # Default color
            if protocol == 'TCP':
                color = TermColors.BLUE
            elif protocol == 'UDP':
                color = TermColors.RED
            elif protocol == 'ICMP':
                color = TermColors.GREEN
                
            # Create bar
            bar = self.horizontal_bar(count, max_count)
            
            # Print protocol with count and bar
            print(f"{protocol.ljust(8)}: {self.format_number(count).rjust(7)} {color}{bar}{TermColors.ENDC}")
            
        print()
    
    def print_top_talkers(self, n=10):
        """Print top talkers as horizontal bars"""
        talkers = self.parser.get_top_talkers(n)
        
        if not talkers:
            return
            
        self.print_header(f"TOP {len(talkers)} TALKERS (SOURCE IP)")
        
        # Get maximum count for scaling
        max_count = max(talkers.values()) if talkers else 0
        
        # Print each talker
        for ip, count in talkers.items():
            # Create bar
            bar = self.horizontal_bar(count, max_count)
            
            # Print IP with count and bar
            print(f"{ip.ljust(15)}: {self.format_number(count).rjust(7)} {TermColors.YELLOW}{bar}{TermColors.ENDC}")
            
        print()
    
    def print_traffic_volume(self, bins=20):
        """Print traffic volume over time as ASCII line graph"""
        bin_times, bin_volumes = self.parser.get_traffic_volume_over_time(bins)
        
        if not bin_times or not bin_volumes:
            return
            
        self.print_header("TRAFFIC VOLUME OVER TIME")
        
        # Get maximum volume for scaling
        max_volume = max(bin_volumes) if bin_volumes else 0
        
        # Determine graph height
        graph_height = min(self.height // 2, 10)
        
        # Create empty graph
        graph = [[' ' for _ in range(bins)] for _ in range(graph_height)]
        
        # Fill graph with data points
        for i, volume in enumerate(bin_volumes):
            if max_volume > 0:
                # Calculate height of this data point
                height = int((volume / max_volume) * (graph_height - 1))
                
                # Fill graph column
                for j in range(graph_height - 1, graph_height - height - 2, -1):
                    if j >= 0:
                        graph[j][i] = '█'
                        
        # Print graph (bottom to top)
        for i in range(graph_height - 1, -1, -1):
            line = ''.join(graph[i])
            print(f"{TermColors.GREEN}{line}{TermColors.ENDC}")
            
        # Print x-axis
        print(f"{TermColors.BLUE}{'▔' * bins}{TermColors.ENDC}")
        
        # Print x-axis labels
        if self.parser.start_time and self.parser.end_time:
            start = datetime.fromtimestamp(self.parser.start_time).strftime('%H:%M:%S')
            end = datetime.fromtimestamp(self.parser.end_time).strftime('%H:%M:%S')
            print(f"{start.ljust(8)}{' ' * (bins - 16)}{end.rjust(8)}")
            
        # Print volume range
        print(f"Max Volume: {self.format_number(max_volume)} bytes")
        print()
    
    def print_packet_size_distribution(self, bins=10):
        """Print packet size distribution as horizontal bars"""
        bin_edges, bin_counts = self.parser.get_packet_size_distribution(bins)
        
        if not bin_edges or not bin_counts:
            return
            
        self.print_header("PACKET SIZE DISTRIBUTION")
        
        # Get maximum count for scaling
        max_count = max(bin_counts) if bin_counts else 0
        
        # Print each bin
        for i in range(len(bin_edges)):
            if i < len(bin_counts):
                # Determine bin label
                if i < len(bin_edges) - 1:
                    label = f"{int(bin_edges[i])}-{int(bin_edges[i+1] - 1)}"
                else:
                    label = f"{int(bin_edges[i])}+"
                    
                # Create bar
                bar = self.horizontal_bar(bin_counts[i], max_count)
                
                # Print bin with count and bar
                print(f"{label.ljust(12)}: {self.format_number(bin_counts[i]).rjust(7)} {TermColors.CYAN}{bar}{TermColors.ENDC}")
                
        print()
    
    def print_connection_map(self):
        """Print a map of connections between hosts"""
        connections = self.parser.get_connections()
        
        if not connections:
            return
            
        self.print_header("CONNECTION MAP")
        
        # Limit number of connections to display
        max_connections = self.height - 5
        if len(connections) > max_connections:
            print(f"Showing top {max_connections} connections out of {len(connections)} total")
            connections = connections[:max_connections]
            
        # Print each connection
        for src, dst in connections:
            print(f"{TermColors.BLUE}{src}{TermColors.ENDC} {TermColors.YELLOW}→{TermColors.ENDC} {TermColors.RED}{dst}{TermColors.ENDC}")
            
        print()


def main():
    """Main function to run the CLI visualizer"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="NetHunter CLI Packet Visualizer")
    parser.add_argument("pcap", help="PCAP file to visualize")
    parser.add_argument("--height", type=int, default=20, help="Height of graphs (lines)")
    parser.add_argument("--width", type=int, default=80, help="Width of graphs (columns)")
    parser.add_argument("--bins", type=int, default=20, help="Number of bins for histograms")
    parser.add_argument("--top", type=int, default=10, help="Number of top talkers to show")
    args = parser.parse_args()
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        print(f"{TermColors.RED}Error: Scapy is required for PCAP parsing.{TermColors.ENDC}")
        print(f"{TermColors.YELLOW}Please install Scapy: pip install scapy{TermColors.ENDC}")
        sys.exit(1)
    
    # Check if pcap file exists
    if not os.path.isfile(args.pcap):
        print(f"{TermColors.RED}Error: PCAP file not found: {args.pcap}{TermColors.ENDC}")
        sys.exit(1)
    
    # Create parser and visualizer
    packet_parser = PacketParser()
    visualizer = CLIVisualizer(packet_parser, args.width, args.height)
    
    # Print title
    title = "NetHunter CLI Packet Visualizer"
    print(f"\n{TermColors.BOLD}{TermColors.GREEN}{title.center(args.width)}{TermColors.ENDC}\n")
    
    # Load PCAP file
    print(f"{TermColors.YELLOW}Loading PCAP file: {args.pcap}{TermColors.ENDC}")
    start_time = time.time()
    
    if not packet_parser.load_pcap(args.pcap):
        print(f"{TermColors.RED}Error: Failed to load PCAP file.{TermColors.ENDC}")
        sys.exit(1)
        
    load_time = time.time() - start_time
    print(f"{TermColors.GREEN}Loaded {packet_parser.packet_count} packets in {load_time:.2f} seconds{TermColors.ENDC}")
    
    # Print visualizations
    visualizer.print_capture_summary()
    visualizer.print_protocol_distribution()
    visualizer.print_transport_protocol_distribution()
    visualizer.print_top_talkers(args.top)
    visualizer.print_traffic_volume(args.bins)
    visualizer.print_packet_size_distribution(args.bins)
    visualizer.print_connection_map()
    
    # Print footer
    print(f"\n{TermColors.BOLD}{TermColors.GREEN}{'=' * args.width}{TermColors.ENDC}")
    print(f"{TermColors.BOLD}{TermColors.GREEN}Analysis Complete{TermColors.ENDC}\n")


if __name__ == "__main__":
    main()