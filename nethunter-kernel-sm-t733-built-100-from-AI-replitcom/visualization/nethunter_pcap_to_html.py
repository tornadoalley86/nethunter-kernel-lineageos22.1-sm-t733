#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetHunter PCAP to HTML Converter

This tool generates interactive HTML reports from PCAP files for network packet analysis.
The HTML reports can be viewed in any browser and include interactive charts and tables.

Features:
- Protocol distribution
- Time-series traffic analysis
- Top talkers (source and destination)
- Connection graphs
- Packet size analysis
- HTTP request/response analysis
- Export to standalone HTML
"""

import os
import sys
import json
import time
import base64
import argparse
import logging
from datetime import datetime
from collections import defaultdict

# Import pcap parsing libraries with error handling
try:
    from scapy.all import rdpcap, PcapReader
    from scapy.layers import all as scapy_layers
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. PCAP parsing may not work properly.")
    print("Install Scapy with: pip install scapy")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("NetHunterPcapToHtml")

# NetHunter colors
NH_COLORS = {
    'background': '#121212',
    'text': '#E0E0E0',
    'accent1': '#00B0FF',
    'accent2': '#FF4081',
    'accent3': '#76FF03',
    'accent4': '#FFC400',
    'tcp': '#00B0FF',
    'udp': '#FF4081',
    'icmp': '#76FF03',
    'dns': '#FFC400',
    'http': '#651FFF',
    'https': '#304FFE',
    'other': '#78909C',
}

class PacketParser:
    """Handle packet parsing from PCAP files"""
    
    def __init__(self):
        self.packets = []
        self.file_path = None
        self.packet_count = 0
        self.file_size = 0
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
            # Get file size
            self.file_size = os.path.getsize(file_path)
            
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
            'datetime': datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f'),
            'size': len(packet),
            'src': None,
            'dst': None,
            'protocol': None,
            'transport_protocol': None,
            'src_port': None,
            'dst_port': None,
            'ttl': None,
            'flags': None,
            'length': None,
            'http_method': None,
            'http_uri': None,
            'http_version': None,
            'http_host': None,
            'http_status_code': None,
            'http_status_msg': None,
            'http_content_type': None,
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
                
                # Parse HTTP if present
                if packet.haslayer('Raw'):
                    try:
                        http_payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                        
                        # Check for HTTP request
                        if http_payload.startswith('GET ') or http_payload.startswith('POST ') or \
                           http_payload.startswith('PUT ') or http_payload.startswith('DELETE '):
                            request_lines = http_payload.split('\r\n')
                            if request_lines:
                                request_line = request_lines[0].split(' ')
                                if len(request_line) >= 3:
                                    packet_data['http_method'] = request_line[0]
                                    packet_data['http_uri'] = request_line[1]
                                    packet_data['http_version'] = request_line[2]
                                    
                                # Look for Host header
                                for line in request_lines[1:]:
                                    if line.lower().startswith('host:'):
                                        packet_data['http_host'] = line[5:].strip()
                                        break
                                        
                        # Check for HTTP response
                        elif http_payload.startswith('HTTP/'):
                            response_lines = http_payload.split('\r\n')
                            if response_lines:
                                status_line = response_lines[0].split(' ')
                                if len(status_line) >= 3:
                                    packet_data['http_version'] = status_line[0]
                                    packet_data['http_status_code'] = status_line[1]
                                    packet_data['http_status_msg'] = ' '.join(status_line[2:])
                                    
                                # Look for Content-Type header
                                for line in response_lines[1:]:
                                    if line.lower().startswith('content-type:'):
                                        packet_data['http_content_type'] = line[13:].strip()
                                        break
                    except:
                        pass
                        
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
    
    def get_capture_summary(self):
        """Get summary of the capture file"""
        filename = os.path.basename(self.file_path) if self.file_path else "Unknown"
        filesize_mb = round(self.file_size / (1024 * 1024), 2) if self.file_size else 0
        
        start_time = "N/A"
        end_time = "N/A"
        duration = "N/A"
        
        if self.start_time:
            start_time = datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')
        if self.end_time:
            end_time = datetime.fromtimestamp(self.end_time).strftime('%Y-%m-%d %H:%M:%S')
        if self.duration:
            duration = f"{self.duration:.2f} seconds"
            
        return {
            'filename': filename,
            'filesize': filesize_mb,
            'packets': self.packet_count,
            'start_time': start_time,
            'end_time': end_time,
            'duration': duration
        }
    
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
    
    def get_top_sources(self, n=10):
        """Get the top n source IP addresses"""
        sources = {}
        
        for packet in self.packets:
            src = packet['src']
            if src:
                if src in sources:
                    sources[src] += 1
                else:
                    sources[src] = 1
                    
        # Sort by count (descending) and take top n
        sources = dict(sorted(sources.items(), key=lambda x: x[1], reverse=True)[:n])
        return sources
    
    def get_top_destinations(self, n=10):
        """Get the top n destination IP addresses"""
        destinations = {}
        
        for packet in self.packets:
            dst = packet['dst']
            if dst:
                if dst in destinations:
                    destinations[dst] += 1
                else:
                    destinations[dst] = 1
                    
        # Sort by count (descending) and take top n
        destinations = dict(sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:n])
        return destinations
    
    def get_traffic_volume_over_time(self, bins=50):
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
            bin_times.append(datetime.fromtimestamp(bin_time).strftime('%H:%M:%S'))
            
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
        bin_labels = []
        bin_counts = [0] * bins
        
        # Calculate bin edges
        for i in range(bins):
            bin_edge = min_size + (i * bin_size)
            bin_edge_end = min_size + ((i + 1) * bin_size) - 1
            bin_labels.append(f"{int(bin_edge)}-{int(bin_edge_end)}")
            
        # Count packets in each bin
        for size in sizes:
            # Determine which bin this packet belongs to
            bin_index = min(int((size - min_size) / bin_size), bins - 1)
            bin_counts[bin_index] += 1
            
        return bin_labels, bin_counts
    
    def get_connections(self, max_connections=100):
        """Get unique connections between hosts"""
        connections = {}
        
        for packet in self.packets:
            src = packet['src']
            dst = packet['dst']
            if src and dst:
                key = f"{src},{dst}"
                if key in connections:
                    connections[key]['count'] += 1
                    connections[key]['bytes'] += packet['size']
                else:
                    connections[key] = {
                        'source': src,
                        'destination': dst,
                        'count': 1,
                        'bytes': packet['size']
                    }
                    
        # Sort by packet count and take top connections
        connections = sorted(connections.values(), key=lambda x: x['count'], reverse=True)[:max_connections]
        return connections
    
    def get_http_requests(self, max_requests=100):
        """Get HTTP requests from the capture"""
        http_requests = []
        
        for packet in self.packets:
            if packet['protocol'] == 'HTTP' and packet['http_method'] and packet['http_uri']:
                host = packet['http_host'] or packet['dst']
                timestamp = packet['datetime']
                
                http_requests.append({
                    'timestamp': timestamp,
                    'method': packet['http_method'],
                    'host': host,
                    'uri': packet['http_uri'],
                    'src': packet['src'],
                    'dst': packet['dst'],
                    'src_port': packet['src_port'],
                    'dst_port': packet['dst_port']
                })
                
        # Sort by timestamp and take most recent requests
        http_requests = sorted(http_requests, key=lambda x: x['timestamp'])[-max_requests:]
        return http_requests
    
    def get_http_responses(self, max_responses=100):
        """Get HTTP responses from the capture"""
        http_responses = []
        
        for packet in self.packets:
            if packet['protocol'] == 'HTTP' and packet['http_status_code']:
                timestamp = packet['datetime']
                
                http_responses.append({
                    'timestamp': timestamp,
                    'status': packet['http_status_code'],
                    'message': packet['http_status_msg'],
                    'content_type': packet['http_content_type'],
                    'src': packet['src'],
                    'dst': packet['dst'],
                    'src_port': packet['src_port'],
                    'dst_port': packet['dst_port']
                })
                
        # Sort by timestamp and take most recent responses
        http_responses = sorted(http_responses, key=lambda x: x['timestamp'])[-max_responses:]
        return http_responses
    
    def get_raw_packets(self, max_packets=100):
        """Get raw packet data for display"""
        raw_packets = []
        
        for i, packet in enumerate(self.packets[-max_packets:]):
            raw_packets.append({
                'number': self.packet_count - max_packets + i + 1,
                'time': packet['datetime'],
                'src': packet['src'],
                'src_port': packet['src_port'],
                'dst': packet['dst'],
                'dst_port': packet['dst_port'],
                'protocol': packet['protocol'],
                'length': packet['size'],
                'ttl': packet['ttl']
            })
            
        return raw_packets


class HtmlReport:
    """Generate HTML report from packet data"""
    
    def __init__(self, parser):
        self.parser = parser
        
    def generate_html(self):
        """Generate HTML report content"""
        # Get data for report
        summary = self.parser.get_capture_summary()
        protocols = self.parser.get_protocol_distribution()
        transport_protocols = self.parser.get_transport_protocol_distribution()
        top_sources = self.parser.get_top_sources()
        top_destinations = self.parser.get_top_destinations()
        bin_times, bin_volumes = self.parser.get_traffic_volume_over_time()
        bin_labels, bin_counts = self.parser.get_packet_size_distribution()
        connections = self.parser.get_connections()
        http_requests = self.parser.get_http_requests()
        http_responses = self.parser.get_http_responses()
        raw_packets = self.parser.get_raw_packets()
        
        # Convert data to JSON for JavaScript
        data_json = json.dumps({
            'summary': summary,
            'protocols': protocols,
            'transport_protocols': transport_protocols,
            'top_sources': top_sources,
            'top_destinations': top_destinations,
            'traffic_time': bin_times,
            'traffic_volume': bin_volumes,
            'packet_size_labels': bin_labels,
            'packet_size_counts': bin_counts,
            'connections': connections,
            'http_requests': http_requests,
            'http_responses': http_responses,
            'raw_packets': raw_packets,
            'colors': NH_COLORS
        })
        
        # Create HTML report
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetHunter Packet Analysis: {summary['filename']}</title>
    <style>
        :root {{
            --background: {NH_COLORS['background']};
            --text: {NH_COLORS['text']};
            --accent1: {NH_COLORS['accent1']};
            --accent2: {NH_COLORS['accent2']};
            --accent3: {NH_COLORS['accent3']};
            --accent4: {NH_COLORS['accent4']};
            --tcp: {NH_COLORS['tcp']};
            --udp: {NH_COLORS['udp']};
            --icmp: {NH_COLORS['icmp']};
            --dns: {NH_COLORS['dns']};
            --http: {NH_COLORS['http']};
            --https: {NH_COLORS['https']};
            --other: {NH_COLORS['other']};
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--background);
            color: var(--text);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background-color: #1a1a1a;
            padding: 20px;
            border-bottom: 3px solid var(--accent1);
            margin-bottom: 30px;
        }}
        
        header h1 {{
            margin: 0;
            font-size: 24px;
            display: flex;
            align-items: center;
        }}
        
        header .logo {{
            height: 40px;
            margin-right: 10px;
        }}
        
        .section {{
            background-color: #1a1a1a;
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }}
        
        .section h2 {{
            margin-top: 0;
            border-bottom: 2px solid var(--accent1);
            padding-bottom: 10px;
            color: var(--accent1);
        }}
        
        .card {{
            background-color: #252525;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
        }}
        
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        
        @media (max-width: 768px) {{
            .grid-2 {{
                grid-template-columns: 1fr;
            }}
        }}
        
        .summary-item {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
        }}
        
        .summary-item .label {{
            font-weight: bold;
            color: var(--accent4);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 10px;
        }}
        
        table th, table td {{
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        
        table th {{
            background-color: #1a1a1a;
            color: var(--accent1);
        }}
        
        table tr:hover {{
            background-color: #2a2a2a;
        }}
        
        .tabs {{
            margin-bottom: 15px;
        }}
        
        .tab-buttons {{
            display: flex;
            overflow-x: auto;
        }}
        
        .tab-button {{
            padding: 10px 15px;
            background-color: #2a2a2a;
            color: var(--text);
            border: none;
            cursor: pointer;
            outline: none;
            margin-right: 5px;
            border-radius: 5px 5px 0 0;
        }}
        
        .tab-button.active {{
            background-color: var(--accent1);
            color: var(--background);
        }}
        
        .tab-content {{
            display: none;
            padding: 15px;
            background-color: #252525;
            border-radius: 0 0 5px 5px;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            margin-top: 30px;
            border-top: 1px solid #333;
            font-size: 12px;
            color: #888;
        }}
        
        /* Protocol specific colors */
        .tcp {{ color: var(--tcp); }}
        .udp {{ color: var(--udp); }}
        .icmp {{ color: var(--icmp); }}
        .dns {{ color: var(--dns); }}
        .http {{ color: var(--http); }}
        .https {{ color: var(--https); }}
        .other {{ color: var(--other); }}
        
        /* Canvas styling */
        canvas {{
            max-width: 100%;
            height: auto;
            margin-bottom: 15px;
        }}
        
        .connection-map {{
            border: 1px solid #333;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            height: 400px;
            overflow: hidden;
        }}
        
        #search {{
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            background-color: #333;
            border: 1px solid #444;
            color: var(--text);
            border-radius: 3px;
        }}
        
        .pagination {{
            display: flex;
            justify-content: center;
            margin: 15px 0;
        }}
        
        .pagination button {{
            padding: 5px 10px;
            margin: 0 5px;
            background-color: #2a2a2a;
            color: var(--text);
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }}
        
        .pagination button:hover {{
            background-color: var(--accent1);
            color: var(--background);
        }}
        
        .pagination button:disabled {{
            background-color: #1a1a1a;
            color: #666;
            cursor: not-allowed;
        }}
        
        .pagination-info {{
            text-align: center;
            margin-bottom: 10px;
            font-size: 14px;
            color: #888;
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>
                <svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="{NH_COLORS['accent1']}">
                    <path d="M184 0c30.9 0 56 25.1 56 56V456c0 30.9-25.1 56-56 56c-28.9 0-52.6-21.9-55.7-50.1c-5.2 1.4-10.7 2.1-16.3 2.1c-35.3 0-64-28.7-64-64c0-7.4 1.3-14.6 3.6-21.2C21.4 367.4 0 338.2 0 304c0-31.9 18.7-59.5 45.8-72.3C37.8 220.8 32 208 32 194c0-18.6 10.2-34.9 25.2-43.7C56.4 145.4 56 140.5 56 135.5c0-35.5 28.9-64.4 64.4-64.4c6.9 0 13.5 1.1 19.8 3.1C152.4 46.6 180.5 28 212 28c1.2 0 2.4 0 3.6 .1C211.3 15.9 199 0 184 0zM328 0c-30.9 0-56 25.1-56 56V456c0 30.9 25.1 56 56 56c28.9 0 52.6-21.9 55.7-50.1c5.2 1.4 10.7 2.1 16.3 2.1c35.3 0 64-28.7 64-64c0-7.4-1.3-14.6-3.6-21.2C490.6 367.4 512 338.2 512 304c0-31.9-18.7-59.5-45.8-72.3c8-10.9 13.8-23.7 13.8-37.7c0-18.6-10.2-34.9-25.2-43.7c.8-4.9 1.2-9.8 1.2-14.8c0-35.5-28.9-64.4-64.4-64.4c-6.9 0-13.5 1.1-19.8 3.1C359.6 46.6 331.5 28 300 28c-1.2 0-2.4 0-3.6 .1C300.7 15.9 313 0 328 0z"/>
                </svg>
                NetHunter Packet Analysis: {summary['filename']}
            </h1>
        </div>
    </header>
    
    <div class="container">
        <!-- Summary Section -->
        <section class="section" id="summary">
            <h2>Capture Summary</h2>
            <div class="card">
                <div class="summary-item">
                    <span class="label">Filename:</span>
                    <span>{summary['filename']}</span>
                </div>
                <div class="summary-item">
                    <span class="label">File Size:</span>
                    <span>{summary['filesize']} MB</span>
                </div>
                <div class="summary-item">
                    <span class="label">Packets:</span>
                    <span>{summary['packets']}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Start Time:</span>
                    <span>{summary['start_time']}</span>
                </div>
                <div class="summary-item">
                    <span class="label">End Time:</span>
                    <span>{summary['end_time']}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Duration:</span>
                    <span>{summary['duration']}</span>
                </div>
            </div>
        </section>
        
        <!-- Protocol Distribution Section -->
        <div class="grid-2">
            <section class="section" id="protocols">
                <h2>Protocol Distribution</h2>
                <div class="card">
                    <canvas id="protocolChart"></canvas>
                </div>
            </section>
            
            <section class="section" id="transport-protocols">
                <h2>Transport Protocol Distribution</h2>
                <div class="card">
                    <canvas id="transportChart"></canvas>
                </div>
            </section>
        </div>
        
        <!-- Traffic Analysis Section -->
        <section class="section" id="traffic">
            <h2>Traffic Analysis</h2>
            <div class="card">
                <canvas id="trafficChart"></canvas>
            </div>
        </section>
        
        <!-- Top Talkers Section -->
        <div class="grid-2">
            <section class="section" id="sources">
                <h2>Top Source IPs</h2>
                <div class="card">
                    <canvas id="sourcesChart"></canvas>
                </div>
            </section>
            
            <section class="section" id="destinations">
                <h2>Top Destination IPs</h2>
                <div class="card">
                    <canvas id="destinationsChart"></canvas>
                </div>
            </section>
        </div>
        
        <!-- Packet Size Distribution Section -->
        <section class="section" id="packet-sizes">
            <h2>Packet Size Distribution</h2>
            <div class="card">
                <canvas id="packetSizeChart"></canvas>
            </div>
        </section>
        
        <!-- Connection Graph Section -->
        <section class="section" id="connections">
            <h2>Connection Graph</h2>
            <div class="card">
                <div class="connection-map" id="connectionMap"></div>
            </div>
        </section>
        
        <!-- HTTP Analysis Section -->
        <section class="section" id="http-analysis">
            <h2>HTTP Analysis</h2>
            
            <div class="tabs">
                <div class="tab-buttons">
                    <button class="tab-button active" data-tab="requests">HTTP Requests</button>
                    <button class="tab-button" data-tab="responses">HTTP Responses</button>
                </div>
                
                <div class="tab-content active" id="requests">
                    <input type="text" id="search-requests" placeholder="Search requests...">
                    <table id="requestsTable">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Method</th>
                                <th>Host</th>
                                <th>URI</th>
                                <th>Source</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Filled by JavaScript -->
                        </tbody>
                    </table>
                    <div class="pagination" id="requests-pagination">
                        <button id="requests-prev" disabled>&laquo; Previous</button>
                        <button id="requests-next">Next &raquo;</button>
                    </div>
                    <div class="pagination-info" id="requests-pagination-info"></div>
                </div>
                
                <div class="tab-content" id="responses">
                    <input type="text" id="search-responses" placeholder="Search responses...">
                    <table id="responsesTable">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Status</th>
                                <th>Message</th>
                                <th>Content Type</th>
                                <th>Source</th>
                                <th>Destination</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Filled by JavaScript -->
                        </tbody>
                    </table>
                    <div class="pagination" id="responses-pagination">
                        <button id="responses-prev" disabled>&laquo; Previous</button>
                        <button id="responses-next">Next &raquo;</button>
                    </div>
                    <div class="pagination-info" id="responses-pagination-info"></div>
                </div>
            </div>
        </section>
        
        <!-- Raw Packets Section -->
        <section class="section" id="raw-packets">
            <h2>Raw Packets</h2>
            <div class="card">
                <input type="text" id="search-packets" placeholder="Search packets...">
                <table id="packetsTable">
                    <thead>
                        <tr>
                            <th>No.</th>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Length</th>
                            <th>Info</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Filled by JavaScript -->
                    </tbody>
                </table>
                <div class="pagination" id="packets-pagination">
                    <button id="packets-prev" disabled>&laquo; Previous</button>
                    <button id="packets-next">Next &raquo;</button>
                </div>
                <div class="pagination-info" id="packets-pagination-info"></div>
            </div>
        </section>
    </div>
    
    <footer>
        <div class="container">
            Generated by NetHunter Packet Analyzer on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Created for Samsung Galaxy Tab S7 FE (SM-T733)
        </div>
    </footer>
    
    <!-- Chart.js for visualizations -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
    
    <!-- D3.js for network graph -->
    <script src="https://d3js.org/d3.v7.min.js"></script>
    
    <script>
        // Parse data from JSON
        const data = {data_json};
        
        // Function to get protocol color
        function getProtocolColor(protocol) {{
            const lowerProto = protocol.toLowerCase();
            if (data.colors[lowerProto]) {{
                return data.colors[lowerProto];
            }}
            return data.colors.other;
        }}
        
        // Initialize charts when DOM is loaded
        document.addEventListener('DOMContentLoaded', function() {{
            // Protocol Distribution Chart
            const protocolCtx = document.getElementById('protocolChart').getContext('2d');
            const protocolLabels = Object.keys(data.protocols);
            const protocolValues = Object.values(data.protocols);
            const protocolColors = protocolLabels.map(protocol => getProtocolColor(protocol));
            
            new Chart(protocolCtx, {{
                type: 'pie',
                data: {{
                    labels: protocolLabels,
                    datasets: [{{
                        data: protocolValues,
                        backgroundColor: protocolColors,
                        borderColor: data.colors.background,
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            position: 'right',
                            labels: {{
                                color: data.colors.text
                            }}
                        }},
                        title: {{
                            display: false,
                            text: 'Protocol Distribution'
                        }}
                    }}
                }}
            }});
            
            // Transport Protocol Distribution Chart
            const transportCtx = document.getElementById('transportChart').getContext('2d');
            const transportLabels = Object.keys(data.transport_protocols);
            const transportValues = Object.values(data.transport_protocols);
            const transportColors = transportLabels.map(protocol => getProtocolColor(protocol));
            
            new Chart(transportCtx, {{
                type: 'doughnut',
                data: {{
                    labels: transportLabels,
                    datasets: [{{
                        data: transportValues,
                        backgroundColor: transportColors,
                        borderColor: data.colors.background,
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            position: 'right',
                            labels: {{
                                color: data.colors.text
                            }}
                        }},
                        title: {{
                            display: false,
                            text: 'Transport Protocol Distribution'
                        }}
                    }}
                }}
            }});
            
            // Traffic Volume Over Time Chart
            const trafficCtx = document.getElementById('trafficChart').getContext('2d');
            
            new Chart(trafficCtx, {{
                type: 'line',
                data: {{
                    labels: data.traffic_time,
                    datasets: [{{
                        label: 'Traffic Volume (bytes)',
                        data: data.traffic_volume,
                        backgroundColor: data.colors.accent1,
                        borderColor: data.colors.accent1,
                        tension: 0.2,
                        pointRadius: 2,
                        pointHoverRadius: 5
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        x: {{
                            title: {{
                                display: true,
                                text: 'Time',
                                color: data.colors.text
                            }},
                            ticks: {{
                                color: data.colors.text
                            }},
                            grid: {{
                                color: 'rgba(255, 255, 255, 0.1)'
                            }}
                        }},
                        y: {{
                            title: {{
                                display: true,
                                text: 'Bytes',
                                color: data.colors.text
                            }},
                            ticks: {{
                                color: data.colors.text
                            }},
                            grid: {{
                                color: 'rgba(255, 255, 255, 0.1)'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            labels: {{
                                color: data.colors.text
                            }}
                        }}
                    }}
                }}
            }});
            
            // Top Sources Chart
            const sourcesCtx = document.getElementById('sourcesChart').getContext('2d');
            const sourceLabels = Object.keys(data.top_sources);
            const sourceValues = Object.values(data.top_sources);
            
            new Chart(sourcesCtx, {{
                type: 'bar',
                data: {{
                    labels: sourceLabels,
                    datasets: [{{
                        label: 'Packet Count',
                        data: sourceValues,
                        backgroundColor: data.colors.accent2
                    }}]
                }},
                options: {{
                    responsive: true,
                    indexAxis: 'y',
                    scales: {{
                        x: {{
                            title: {{
                                display: true,
                                text: 'Packet Count',
                                color: data.colors.text
                            }},
                            ticks: {{
                                color: data.colors.text
                            }},
                            grid: {{
                                color: 'rgba(255, 255, 255, 0.1)'
                            }}
                        }},
                        y: {{
                            title: {{
                                display: true,
                                text: 'IP Address',
                                color: data.colors.text
                            }},
                            ticks: {{
                                color: data.colors.text
                            }},
                            grid: {{
                                color: 'rgba(255, 255, 255, 0.1)'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            labels: {{
                                color: data.colors.text
                            }}
                        }}
                    }}
                }}
            }});
            
            // Top Destinations Chart
            const destinationsCtx = document.getElementById('destinationsChart').getContext('2d');
            const destinationLabels = Object.keys(data.top_destinations);
            const destinationValues = Object.values(data.top_destinations);
            
            new Chart(destinationsCtx, {{
                type: 'bar',
                data: {{
                    labels: destinationLabels,
                    datasets: [{{
                        label: 'Packet Count',
                        data: destinationValues,
                        backgroundColor: data.colors.accent3
                    }}]
                }},
                options: {{
                    responsive: true,
                    indexAxis: 'y',
                    scales: {{
                        x: {{
                            title: {{
                                display: true,
                                text: 'Packet Count',
                                color: data.colors.text
                            }},
                            ticks: {{
                                color: data.colors.text
                            }},
                            grid: {{
                                color: 'rgba(255, 255, 255, 0.1)'
                            }}
                        }},
                        y: {{
                            title: {{
                                display: true,
                                text: 'IP Address',
                                color: data.colors.text
                            }},
                            ticks: {{
                                color: data.colors.text
                            }},
                            grid: {{
                                color: 'rgba(255, 255, 255, 0.1)'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            labels: {{
                                color: data.colors.text
                            }}
                        }}
                    }}
                }}
            }});
            
            // Packet Size Distribution Chart
            const packetSizeCtx = document.getElementById('packetSizeChart').getContext('2d');
            
            new Chart(packetSizeCtx, {{
                type: 'bar',
                data: {{
                    labels: data.packet_size_labels,
                    datasets: [{{
                        label: 'Packet Count',
                        data: data.packet_size_counts,
                        backgroundColor: data.colors.accent4
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        x: {{
                            title: {{
                                display: true,
                                text: 'Packet Size (bytes)',
                                color: data.colors.text
                            }},
                            ticks: {{
                                color: data.colors.text
                            }},
                            grid: {{
                                color: 'rgba(255, 255, 255, 0.1)'
                            }}
                        }},
                        y: {{
                            title: {{
                                display: true,
                                text: 'Count',
                                color: data.colors.text
                            }},
                            ticks: {{
                                color: data.colors.text
                            }},
                            grid: {{
                                color: 'rgba(255, 255, 255, 0.1)'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            labels: {{
                                color: data.colors.text
                            }}
                        }}
                    }}
                }}
            }});
            
            // Connection Graph
            createConnectionGraph(data.connections);
            
            // Fill tables with data
            fillHttpRequestsTable(data.http_requests);
            fillHttpResponsesTable(data.http_responses);
            fillPacketsTable(data.raw_packets);
            
            // Set up tab switching
            setupTabs();
        }});
        
        // Create connection graph using D3.js
        function createConnectionGraph(connections) {{
            // Exit if no connections or D3 not available
            if (!connections || connections.length === 0 || !window.d3) {{
                return;
            }}
            
            const width = document.getElementById('connectionMap').clientWidth;
            const height = document.getElementById('connectionMap').clientHeight;
            
            // Create unique nodes list
            const nodes = [];
            const nodeMap = new Map();
            
            // Add all sources and destinations as nodes
            connections.forEach(conn => {{
                if (!nodeMap.has(conn.source)) {{
                    const node = {{
                        id: conn.source,
                        count: 0
                    }};
                    nodes.push(node);
                    nodeMap.set(conn.source, node);
                }}
                
                if (!nodeMap.has(conn.destination)) {{
                    const node = {{
                        id: conn.destination,
                        count: 0
                    }};
                    nodes.push(node);
                    nodeMap.set(conn.destination, node);
                }}
                
                // Update node counts
                nodeMap.get(conn.source).count += conn.count;
                nodeMap.get(conn.destination).count += conn.count;
            }});
            
            // Create links from connections
            const links = connections.map(conn => ({{
                source: conn.source,
                target: conn.destination,
                value: conn.count
            }}));
            
            // Clear previous graph
            d3.select('#connectionMap').select('svg').remove();
            
            // Create SVG container
            const svg = d3.select('#connectionMap')
                .append('svg')
                .attr('width', width)
                .attr('height', height);
                
            // Create force simulation
            const simulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('collision', d3.forceCollide().radius(d => Math.sqrt(d.count) + 10));
                
            // Create links
            const link = svg.append('g')
                .selectAll('line')
                .data(links)
                .enter()
                .append('line')
                .attr('stroke', data.colors.accent1)
                .attr('stroke-opacity', 0.6)
                .attr('stroke-width', d => Math.sqrt(d.value) / 2);
                
            // Create nodes
            const node = svg.append('g')
                .selectAll('circle')
                .data(nodes)
                .enter()
                .append('circle')
                .attr('r', d => 3 + Math.sqrt(d.count) / 2)
                .attr('fill', data.colors.accent2)
                .call(drag(simulation));
                
            // Create node labels
            const label = svg.append('g')
                .selectAll('text')
                .data(nodes)
                .enter()
                .append('text')
                .attr('font-size', 10)
                .attr('dx', 12)
                .attr('dy', 4)
                .text(d => d.id)
                .attr('fill', data.colors.text);
                
            // Update positions on simulation tick
            simulation.on('tick', () => {{
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                    
                node
                    .attr('cx', d => d.x)
                    .attr('cy', d => d.y);
                    
                label
                    .attr('x', d => d.x)
                    .attr('y', d => d.y);
            }});
            
            // Drag functionality
            function drag(simulation) {{
                function dragstarted(event) {{
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    event.subject.fx = event.subject.x;
                    event.subject.fy = event.subject.y;
                }}
                
                function dragged(event) {{
                    event.subject.fx = event.x;
                    event.subject.fy = event.y;
                }}
                
                function dragended(event) {{
                    if (!event.active) simulation.alphaTarget(0);
                    event.subject.fx = null;
                    event.subject.fy = null;
                }}
                
                return d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended);
            }}
        }}
        
        // Pagination state
        const pageState = {{
            requests: {{ currentPage: 1, itemsPerPage: 10, filteredData: [] }},
            responses: {{ currentPage: 1, itemsPerPage: 10, filteredData: [] }},
            packets: {{ currentPage: 1, itemsPerPage: 15, filteredData: [] }}
        }};
        
        // Fill HTTP Requests table with data
        function fillHttpRequestsTable(requests) {{
            pageState.requests.filteredData = [...requests];
            renderRequestsPage();
            
            // Set up search
            document.getElementById('search-requests').addEventListener('input', function(e) {{
                const searchTerm = e.target.value.toLowerCase();
                
                if (searchTerm) {{
                    pageState.requests.filteredData = data.http_requests.filter(req =>
                        req.method.toLowerCase().includes(searchTerm) ||
                        req.host.toLowerCase().includes(searchTerm) ||
                        req.uri.toLowerCase().includes(searchTerm) ||
                        req.src.toLowerCase().includes(searchTerm)
                    );
                }} else {{
                    pageState.requests.filteredData = [...data.http_requests];
                }}
                
                pageState.requests.currentPage = 1;
                renderRequestsPage();
            }});
            
            // Set up pagination
            document.getElementById('requests-prev').addEventListener('click', function() {{
                if (pageState.requests.currentPage > 1) {{
                    pageState.requests.currentPage--;
                    renderRequestsPage();
                }}
            }});
            
            document.getElementById('requests-next').addEventListener('click', function() {{
                const maxPage = Math.ceil(pageState.requests.filteredData.length / pageState.requests.itemsPerPage);
                if (pageState.requests.currentPage < maxPage) {{
                    pageState.requests.currentPage++;
                    renderRequestsPage();
                }}
            }});
        }}
        
        // Render current page of HTTP requests
        function renderRequestsPage() {{
            const { currentPage, itemsPerPage, filteredData } = pageState.requests;
            const startIndex = (currentPage - 1) * itemsPerPage;
            const endIndex = startIndex + itemsPerPage;
            const pageData = filteredData.slice(startIndex, endIndex);
            
            const tbody = document.querySelector('#requestsTable tbody');
            tbody.innerHTML = '';
            
            if (pageData.length === 0) {{
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 5;
                cell.textContent = 'No HTTP requests found';
                cell.style.textAlign = 'center';
                row.appendChild(cell);
                tbody.appendChild(row);
            }} else {{
                pageData.forEach(req => {{
                    const row = document.createElement('tr');
                    
                    const timeCell = document.createElement('td');
                    timeCell.textContent = req.timestamp;
                    row.appendChild(timeCell);
                    
                    const methodCell = document.createElement('td');
                    methodCell.textContent = req.method;
                    methodCell.className = 'http';
                    row.appendChild(methodCell);
                    
                    const hostCell = document.createElement('td');
                    hostCell.textContent = req.host;
                    row.appendChild(hostCell);
                    
                    const uriCell = document.createElement('td');
                    uriCell.textContent = req.uri;
                    row.appendChild(uriCell);
                    
                    const srcCell = document.createElement('td');
                    srcCell.textContent = `${req.src}:${req.src_port}`;
                    row.appendChild(srcCell);
                    
                    tbody.appendChild(row);
                }});
            }}
            
            // Update pagination buttons and info
            const maxPage = Math.ceil(filteredData.length / itemsPerPage);
            document.getElementById('requests-prev').disabled = currentPage <= 1;
            document.getElementById('requests-next').disabled = currentPage >= maxPage;
            
            document.getElementById('requests-pagination-info').textContent = 
                `Page ${currentPage} of ${maxPage || 1} (${filteredData.length} requests)`;
        }}
        
        // Fill HTTP Responses table with data
        function fillHttpResponsesTable(responses) {{
            pageState.responses.filteredData = [...responses];
            renderResponsesPage();
            
            // Set up search
            document.getElementById('search-responses').addEventListener('input', function(e) {{
                const searchTerm = e.target.value.toLowerCase();
                
                if (searchTerm) {{
                    pageState.responses.filteredData = data.http_responses.filter(resp =>
                        (resp.status && resp.status.toLowerCase().includes(searchTerm)) ||
                        (resp.message && resp.message.toLowerCase().includes(searchTerm)) ||
                        (resp.content_type && resp.content_type.toLowerCase().includes(searchTerm)) ||
                        resp.src.toLowerCase().includes(searchTerm) ||
                        resp.dst.toLowerCase().includes(searchTerm)
                    );
                }} else {{
                    pageState.responses.filteredData = [...data.http_responses];
                }}
                
                pageState.responses.currentPage = 1;
                renderResponsesPage();
            }});
            
            // Set up pagination
            document.getElementById('responses-prev').addEventListener('click', function() {{
                if (pageState.responses.currentPage > 1) {{
                    pageState.responses.currentPage--;
                    renderResponsesPage();
                }}
            }});
            
            document.getElementById('responses-next').addEventListener('click', function() {{
                const maxPage = Math.ceil(pageState.responses.filteredData.length / pageState.responses.itemsPerPage);
                if (pageState.responses.currentPage < maxPage) {{
                    pageState.responses.currentPage++;
                    renderResponsesPage();
                }}
            }});
        }}
        
        // Render current page of HTTP responses
        function renderResponsesPage() {{
            const {{ currentPage, itemsPerPage, filteredData }} = pageState.responses;
            const startIndex = (currentPage - 1) * itemsPerPage;
            const endIndex = startIndex + itemsPerPage;
            const pageData = filteredData.slice(startIndex, endIndex);
            
            const tbody = document.querySelector('#responsesTable tbody');
            tbody.innerHTML = '';
            
            if (pageData.length === 0) {{
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 6;
                cell.textContent = 'No HTTP responses found';
                cell.style.textAlign = 'center';
                row.appendChild(cell);
                tbody.appendChild(row);
            }} else {{
                pageData.forEach(resp => {{
                    const row = document.createElement('tr');
                    
                    const timeCell = document.createElement('td');
                    timeCell.textContent = resp.timestamp;
                    row.appendChild(timeCell);
                    
                    const statusCell = document.createElement('td');
                    statusCell.textContent = resp.status || 'N/A';
                    statusCell.className = 'http';
                    row.appendChild(statusCell);
                    
                    const messageCell = document.createElement('td');
                    messageCell.textContent = resp.message || 'N/A';
                    row.appendChild(messageCell);
                    
                    const contentTypeCell = document.createElement('td');
                    contentTypeCell.textContent = resp.content_type || 'N/A';
                    row.appendChild(contentTypeCell);
                    
                    const srcCell = document.createElement('td');
                    srcCell.textContent = `${resp.src}:${resp.src_port}`;
                    row.appendChild(srcCell);
                    
                    const dstCell = document.createElement('td');
                    dstCell.textContent = `${resp.dst}:${resp.dst_port}`;
                    row.appendChild(dstCell);
                    
                    tbody.appendChild(row);
                }});
            }}
            
            // Update pagination buttons and info
            const maxPage = Math.ceil(filteredData.length / itemsPerPage);
            document.getElementById('responses-prev').disabled = currentPage <= 1;
            document.getElementById('responses-next').disabled = currentPage >= maxPage;
            
            document.getElementById('responses-pagination-info').textContent = 
                `Page ${currentPage} of ${maxPage || 1} (${filteredData.length} responses)`;
        }}
        
        // Fill Raw Packets table with data
        function fillPacketsTable(packets) {{
            pageState.packets.filteredData = [...packets];
            renderPacketsPage();
            
            // Set up search
            document.getElementById('search-packets').addEventListener('input', function(e) {{
                const searchTerm = e.target.value.toLowerCase();
                
                if (searchTerm) {{
                    pageState.packets.filteredData = data.raw_packets.filter(packet =>
                        packet.time.toLowerCase().includes(searchTerm) ||
                        packet.src.toLowerCase().includes(searchTerm) ||
                        packet.dst.toLowerCase().includes(searchTerm) ||
                        (packet.protocol && packet.protocol.toLowerCase().includes(searchTerm))
                    );
                }} else {{
                    pageState.packets.filteredData = [...data.raw_packets];
                }}
                
                pageState.packets.currentPage = 1;
                renderPacketsPage();
            }});
            
            // Set up pagination
            document.getElementById('packets-prev').addEventListener('click', function() {{
                if (pageState.packets.currentPage > 1) {{
                    pageState.packets.currentPage--;
                    renderPacketsPage();
                }}
            }});
            
            document.getElementById('packets-next').addEventListener('click', function() {{
                const maxPage = Math.ceil(pageState.packets.filteredData.length / pageState.packets.itemsPerPage);
                if (pageState.packets.currentPage < maxPage) {{
                    pageState.packets.currentPage++;
                    renderPacketsPage();
                }}
            }});
        }}
        
        // Render current page of raw packets
        function renderPacketsPage() {{
            const {{ currentPage, itemsPerPage, filteredData }} = pageState.packets;
            const startIndex = (currentPage - 1) * itemsPerPage;
            const endIndex = startIndex + itemsPerPage;
            const pageData = filteredData.slice(startIndex, endIndex);
            
            const tbody = document.querySelector('#packetsTable tbody');
            tbody.innerHTML = '';
            
            if (pageData.length === 0) {{
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 7;
                cell.textContent = 'No packets found';
                cell.style.textAlign = 'center';
                row.appendChild(cell);
                tbody.appendChild(row);
            }} else {{
                pageData.forEach(packet => {{
                    const row = document.createElement('tr');
                    
                    const numCell = document.createElement('td');
                    numCell.textContent = packet.number;
                    row.appendChild(numCell);
                    
                    const timeCell = document.createElement('td');
                    timeCell.textContent = packet.time;
                    row.appendChild(timeCell);
                    
                    const srcCell = document.createElement('td');
                    srcCell.textContent = packet.src_port ? `${packet.src}:${packet.src_port}` : packet.src;
                    row.appendChild(srcCell);
                    
                    const dstCell = document.createElement('td');
                    dstCell.textContent = packet.dst_port ? `${packet.dst}:${packet.dst_port}` : packet.dst;
                    row.appendChild(dstCell);
                    
                    const protoCell = document.createElement('td');
                    protoCell.textContent = packet.protocol || 'Unknown';
                    protoCell.className = packet.protocol ? packet.protocol.toLowerCase() : 'other';
                    row.appendChild(protoCell);
                    
                    const lengthCell = document.createElement('td');
                    lengthCell.textContent = packet.length;
                    row.appendChild(lengthCell);
                    
                    const infoCell = document.createElement('td');
                    infoCell.textContent = `TTL: ${packet.ttl || 'N/A'}`;
                    row.appendChild(infoCell);
                    
                    tbody.appendChild(row);
                }});
            }}
            
            // Update pagination buttons and info
            const maxPage = Math.ceil(filteredData.length / itemsPerPage);
            document.getElementById('packets-prev').disabled = currentPage <= 1;
            document.getElementById('packets-next').disabled = currentPage >= maxPage;
            
            document.getElementById('packets-pagination-info').textContent = 
                `Page ${currentPage} of ${maxPage || 1} (${filteredData.length} packets)`;
        }}
        
        // Set up tab switching
        function setupTabs() {{
            const tabButtons = document.querySelectorAll('.tab-button');
            const tabContents = document.querySelectorAll('.tab-content');
            
            tabButtons.forEach(button => {{
                button.addEventListener('click', () => {{
                    const tabId = button.getAttribute('data-tab');
                    
                    // Deactivate all tabs
                    tabButtons.forEach(btn => btn.classList.remove('active'));
                    tabContents.forEach(content => content.classList.remove('active'));
                    
                    // Activate selected tab
                    button.classList.add('active');
                    document.getElementById(tabId).classList.add('active');
                }});
            }});
        }}
    </script>
</body>
</html>
"""
        
        return html


def main():
    """Main function to run the PCAP to HTML converter"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="NetHunter PCAP to HTML Converter")
    parser.add_argument("pcap", help="PCAP file to convert")
    parser.add_argument("-o", "--output", help="Output HTML file (default: <pcap_name>.html)")
    args = parser.parse_args()
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        print("Error: Scapy is required for PCAP parsing.")
        print("Please install Scapy: pip install scapy")
        sys.exit(1)
    
    # Check if pcap file exists
    if not os.path.isfile(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    # Determine output file
    if not args.output:
        args.output = os.path.splitext(args.pcap)[0] + '.html'
    
    # Create parser and load PCAP file
    print(f"Loading PCAP file: {args.pcap}")
    start_time = time.time()
    
    packet_parser = PacketParser()
    if not packet_parser.load_pcap(args.pcap):
        print("Error: Failed to load PCAP file.")
        sys.exit(1)
        
    load_time = time.time() - start_time
    print(f"Loaded {packet_parser.packet_count} packets in {load_time:.2f} seconds")
    
    # Generate HTML report
    print("Generating HTML report...")
    html_report = HtmlReport(packet_parser)
    html_content = html_report.generate_html()
    
    # Write HTML to file
    print(f"Writing HTML report to: {args.output}")
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    print(f"HTML report successfully created: {args.output}")
    

if __name__ == "__main__":
    main()