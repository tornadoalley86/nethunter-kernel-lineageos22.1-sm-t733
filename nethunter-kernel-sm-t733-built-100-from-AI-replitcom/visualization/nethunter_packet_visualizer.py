#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetHunter Packet Visualization Tool

This tool provides graphical visualizations for network packet analysis
to enhance the NetHunter penetration testing experience on the Samsung Galaxy Tab S7 FE.

Features:
- Interactive packet flow graphs
- Protocol distribution charts
- Traffic volume analysis
- Endpoint connection mapping
- Attack pattern detection visualization
"""

import os
import sys
import argparse
import logging
import json
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib
matplotlib.use('TkAgg')  # Use TkAgg backend for matplotlib
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import numpy as np
import pandas as pd

# Import pcap parsing libraries with error handling
try:
    import dpkt
    import pyshark
    from scapy.all import rdpcap, PcapReader
    from scapy.layers import all as scapy_layers
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("NetHunterVisualizer")

# Color scheme for NetHunter theme
NH_COLORS = {
    'background': '#121212',  # Dark background
    'text': '#E0E0E0',        # Light text
    'accent1': '#00B0FF',     # Blue accent
    'accent2': '#FF4081',     # Pink accent
    'accent3': '#76FF03',     # Green accent
    'accent4': '#FFC400',     # Amber accent
    'graph_bg': '#1E1E1E',    # Slightly lighter background for graphs
    'tcp': '#00B0FF',         # Blue for TCP
    'udp': '#FF4081',         # Pink for UDP
    'icmp': '#76FF03',        # Green for ICMP
    'dns': '#FFC400',         # Amber for DNS
    'http': '#651FFF',        # Purple for HTTP
    'https': '#304FFE',       # Indigo for HTTPS
    'other': '#78909C',       # Bluish grey for other protocols
}

class PacketParser:
    """Handle packet parsing from different capture formats"""
    
    def __init__(self):
        self.packets = []
        self.dataframe = None
        self.file_path = None
        self.packet_count = 0
        
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
            logger.info(f"Loaded {self.packet_count} packets from {file_path}")
            
            # Convert to pandas DataFrame for easier analysis
            self._create_dataframe()
            return True
            
        except Exception as e:
            logger.error(f"Failed to load PCAP file: {str(e)}")
            return False
    
    def _parse_packet(self, packet):
        """Extract relevant fields from a packet"""
        # Initialize packet data dictionary
        packet_data = {
            'timestamp': float(packet.time),
            'datetime': datetime.datetime.fromtimestamp(float(packet.time)),
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
    
    def _create_dataframe(self):
        """Convert packet list to pandas DataFrame"""
        if not self.packets:
            self.dataframe = pd.DataFrame()
            return
            
        self.dataframe = pd.DataFrame(self.packets)
        
        # Add human-readable timestamp
        if 'timestamp' in self.dataframe.columns:
            self.dataframe['time_str'] = self.dataframe['datetime'].dt.strftime('%H:%M:%S.%f')
            
        # Fill NA values
        self.dataframe = self.dataframe.fillna('N/A')
    
    def get_protocol_distribution(self):
        """Get distribution of protocols in the capture"""
        if self.dataframe is None or self.dataframe.empty:
            return {}
            
        # Count protocol occurrences
        if 'protocol' in self.dataframe.columns:
            protocol_counts = self.dataframe['protocol'].value_counts().to_dict()
            return protocol_counts
        return {}
    
    def get_packet_sizes_over_time(self):
        """Get packet sizes over time for time-based visualization"""
        if self.dataframe is None or self.dataframe.empty:
            return [], []
            
        if 'timestamp' in self.dataframe.columns and 'size' in self.dataframe.columns:
            times = self.dataframe['timestamp'].tolist()
            sizes = self.dataframe['size'].tolist()
            return times, sizes
        return [], []
    
    def get_connections(self):
        """Get unique connections between hosts"""
        if self.dataframe is None or self.dataframe.empty:
            return []
            
        if 'src' in self.dataframe.columns and 'dst' in self.dataframe.columns:
            connections = set()
            for _, row in self.dataframe.iterrows():
                if row['src'] != 'N/A' and row['dst'] != 'N/A':
                    connections.add((row['src'], row['dst']))
            return list(connections)
        return []
        
    def get_top_talkers(self, n=10):
        """Get the top n talking IP addresses"""
        if self.dataframe is None or self.dataframe.empty:
            return {}
            
        if 'src' in self.dataframe.columns:
            # Count packet occurrences by source IP
            src_counts = self.dataframe['src'].value_counts().head(n).to_dict()
            return src_counts
        return {}
        
    def get_transport_protocol_distribution(self):
        """Get distribution of transport protocols"""
        if self.dataframe is None or self.dataframe.empty:
            return {}
            
        if 'transport_protocol' in self.dataframe.columns:
            transport_counts = self.dataframe['transport_protocol'].value_counts().to_dict()
            return transport_counts
        return {}
    
    def get_traffic_volume_over_time(self, window='1S'):
        """Get traffic volume over time, grouped by time window"""
        if self.dataframe is None or self.dataframe.empty:
            return pd.DataFrame()
            
        if 'timestamp' in self.dataframe.columns and 'size' in self.dataframe.columns:
            # Create a time-indexed dataframe
            df = self.dataframe.set_index('datetime')
            # Resample by time window and sum packet sizes
            volume = df.resample(window)['size'].sum().fillna(0)
            return volume
        return pd.DataFrame()


class PacketVisualizer:
    """Generate visualizations for packet analysis"""
    
    def __init__(self, parser):
        self.parser = parser
        self.figure_size = (10, 6)
        
        # Set up matplotlib style for NetHunter theme
        plt.style.use('dark_background')
        matplotlib.rcParams['axes.facecolor'] = NH_COLORS['graph_bg']
        matplotlib.rcParams['figure.facecolor'] = NH_COLORS['background']
        matplotlib.rcParams['text.color'] = NH_COLORS['text']
        matplotlib.rcParams['axes.labelcolor'] = NH_COLORS['text']
        matplotlib.rcParams['xtick.color'] = NH_COLORS['text']
        matplotlib.rcParams['ytick.color'] = NH_COLORS['text']
        
    def plot_protocol_distribution(self):
        """Plot distribution of protocols as a pie chart"""
        protocol_dist = self.parser.get_protocol_distribution()
        
        if not protocol_dist:
            return None
            
        fig, ax = plt.subplots(figsize=self.figure_size)
        
        # Get colors for each protocol
        colors = [NH_COLORS.get(protocol.lower(), NH_COLORS['other']) for protocol in protocol_dist.keys()]
        
        # Create pie chart
        wedges, texts, autotexts = ax.pie(
            protocol_dist.values(), 
            labels=protocol_dist.keys(),
            autopct='%1.1f%%',
            startangle=90,
            colors=colors
        )
        
        # Style the text and percentage labels
        for text in texts:
            text.set_color(NH_COLORS['text'])
        for autotext in autotexts:
            autotext.set_color(NH_COLORS['background'])
            autotext.set_fontweight('bold')
            
        ax.set_title('Protocol Distribution', color=NH_COLORS['text'])
        fig.tight_layout()
        
        return fig
    
    def plot_packet_sizes_over_time(self):
        """Plot packet sizes over time as a scatter plot"""
        times, sizes = self.parser.get_packet_sizes_over_time()
        
        if not times or not sizes:
            return None
            
        fig, ax = plt.subplots(figsize=self.figure_size)
        
        # Normalize timestamps for better visualization
        if times:
            min_time = min(times)
            norm_times = [t - min_time for t in times]
        else:
            norm_times = []
            
        # Create scatter plot of packet sizes
        scatter = ax.scatter(
            norm_times, 
            sizes,
            c=sizes,
            cmap='viridis',
            alpha=0.7,
            edgecolors='w',
            linewidths=0.2
        )
        
        # Add colorbar
        cbar = plt.colorbar(scatter, ax=ax)
        cbar.set_label('Packet Size (bytes)', color=NH_COLORS['text'])
        
        ax.set_title('Packet Sizes Over Time', color=NH_COLORS['text'])
        ax.set_xlabel('Time (seconds)', color=NH_COLORS['text'])
        ax.set_ylabel('Packet Size (bytes)', color=NH_COLORS['text'])
        fig.tight_layout()
        
        return fig
    
    def plot_traffic_volume(self):
        """Plot traffic volume over time as a line graph"""
        volume = self.parser.get_traffic_volume_over_time()
        
        if volume.empty:
            return None
            
        fig, ax = plt.subplots(figsize=self.figure_size)
        
        # Plot traffic volume
        ax.plot(
            volume.index, 
            volume.values,
            color=NH_COLORS['accent1'],
            linewidth=2,
            marker='o',
            markersize=3,
            markerfacecolor=NH_COLORS['accent3'],
            markeredgecolor='white',
            markeredgewidth=0.5
        )
        
        ax.set_title('Traffic Volume Over Time', color=NH_COLORS['text'])
        ax.set_xlabel('Time', color=NH_COLORS['text'])
        ax.set_ylabel('Volume (bytes)', color=NH_COLORS['text'])
        
        # Format x-axis to show time more clearly
        fig.autofmt_xdate()
        
        # Add grid for better readability
        ax.grid(True, linestyle='--', alpha=0.3)
        
        fig.tight_layout()
        return fig
    
    def plot_connection_graph(self):
        """Plot graph of connections between hosts"""
        connections = self.parser.get_connections()
        
        if not connections:
            return None
            
        try:
            import networkx as nx
            
            fig, ax = plt.subplots(figsize=self.figure_size)
            
            # Create graph
            G = nx.DiGraph()
            
            # Add connections
            for src, dst in connections:
                if src not in G:
                    G.add_node(src)
                if dst not in G:
                    G.add_node(dst)
                G.add_edge(src, dst)
            
            # Position nodes using spring layout
            pos = nx.spring_layout(G)
            
            # Draw nodes
            nx.draw_networkx_nodes(
                G, pos,
                node_color=NH_COLORS['accent1'],
                node_size=100,
                alpha=0.8,
                ax=ax
            )
            
            # Draw edges
            nx.draw_networkx_edges(
                G, pos,
                edge_color=NH_COLORS['accent2'],
                width=1.0,
                alpha=0.5,
                arrows=True,
                arrowsize=10,
                ax=ax
            )
            
            # Draw labels with smaller font
            nx.draw_networkx_labels(
                G, pos,
                font_size=8,
                font_color=NH_COLORS['text'],
                ax=ax
            )
            
            ax.set_title('Connection Graph', color=NH_COLORS['text'])
            ax.set_facecolor(NH_COLORS['graph_bg'])
            ax.axis('off')
            
            fig.tight_layout()
            return fig
            
        except ImportError:
            logger.warning("NetworkX not available. Cannot create connection graph.")
            return None
    
    def plot_top_talkers(self):
        """Plot bar chart of top talkers"""
        top_talkers = self.parser.get_top_talkers()
        
        if not top_talkers:
            return None
            
        fig, ax = plt.subplots(figsize=self.figure_size)
        
        # Sort IPs by packet count (descending)
        ips = list(top_talkers.keys())
        counts = list(top_talkers.values())
        
        # Create horizontal bar chart
        bars = ax.barh(
            ips,
            counts,
            color=NH_COLORS['accent1'],
            edgecolor='white',
            linewidth=0.5,
            alpha=0.8
        )
        
        # Add count labels to the bars
        for bar in bars:
            width = bar.get_width()
            label_x_pos = width + 0.5
            ax.text(
                label_x_pos, bar.get_y() + bar.get_height()/2, f'{int(width)}',
                color=NH_COLORS['text'], va='center'
            )
        
        ax.set_title('Top Talkers (Source IP)', color=NH_COLORS['text'])
        ax.set_xlabel('Packet Count', color=NH_COLORS['text'])
        ax.set_ylabel('IP Address', color=NH_COLORS['text'])
        
        # Add grid for better readability
        ax.grid(True, linestyle='--', alpha=0.3)
        
        fig.tight_layout()
        return fig
    
    def plot_transport_protocol_distribution(self):
        """Plot distribution of transport protocols as a bar chart"""
        transport_dist = self.parser.get_transport_protocol_distribution()
        
        if not transport_dist:
            return None
            
        fig, ax = plt.subplots(figsize=self.figure_size)
        
        # Extract protocols and counts
        protocols = list(transport_dist.keys())
        counts = list(transport_dist.values())
        
        # Get colors for each protocol
        colors = [NH_COLORS.get(protocol.lower(), NH_COLORS['other']) for protocol in protocols]
        
        # Create bar chart
        bars = ax.bar(
            protocols,
            counts,
            color=colors,
            edgecolor='white',
            linewidth=0.5,
            alpha=0.8
        )
        
        # Add count labels to the bars
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width()/2, height + 0.1, f'{int(height)}',
                ha='center', va='bottom', color=NH_COLORS['text']
            )
        
        ax.set_title('Transport Protocol Distribution', color=NH_COLORS['text'])
        ax.set_xlabel('Protocol', color=NH_COLORS['text'])
        ax.set_ylabel('Packet Count', color=NH_COLORS['text'])
        
        # Add grid for better readability
        ax.grid(True, linestyle='--', axis='y', alpha=0.3)
        
        fig.tight_layout()
        return fig


class NetHunterPacketVisualizerGUI:
    """GUI for NetHunter Packet Visualizer"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("NetHunter Packet Visualizer")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Set NetHunter dark theme
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Use clam theme as a base
        
        # Configure theme colors
        self.style.configure('.',
                             background=NH_COLORS['background'],
                             foreground=NH_COLORS['text'],
                             fieldbackground=NH_COLORS['background'])
        self.style.configure('TFrame', background=NH_COLORS['background'])
        self.style.configure('TLabel', background=NH_COLORS['background'], foreground=NH_COLORS['text'])
        self.style.configure('TButton', background=NH_COLORS['accent1'], foreground=NH_COLORS['background'])
        self.style.map('TButton',
                       background=[('active', NH_COLORS['accent1']), ('pressed', NH_COLORS['accent3'])],
                       foreground=[('active', NH_COLORS['background']), ('pressed', NH_COLORS['background'])])
        self.style.configure('TNotebook', background=NH_COLORS['background'], tabmargins=[2, 5, 2, 0])
        self.style.configure('TNotebook.Tab', background=NH_COLORS['background'], foreground=NH_COLORS['text'],
                             padding=[10, 2], font=('Helvetica', 10))
        self.style.map('TNotebook.Tab',
                       background=[('selected', NH_COLORS['accent1'])],
                       foreground=[('selected', NH_COLORS['background'])])
        
        # Set window colors
        self.root.configure(bg=NH_COLORS['background'])
        
        # Initialize parser and visualizer
        self.parser = PacketParser()
        self.visualizer = PacketVisualizer(self.parser)
        
        # Create main layout
        self.create_layout()
        
    def create_layout(self):
        """Create the GUI layout"""
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create toolbar
        self.create_toolbar()
        
        # Create notebook for visualization tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs for different visualizations
        self.create_tabs()
        
        # Create status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def create_toolbar(self):
        """Create the toolbar with action buttons"""
        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        # Open PCAP button
        open_btn = ttk.Button(toolbar, text="Open PCAP", command=self.open_pcap)
        open_btn.pack(side=tk.LEFT, padx=5)
        
        # Refresh button
        refresh_btn = ttk.Button(toolbar, text="Refresh Plots", command=self.refresh_plots)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Save Plots button
        save_btn = ttk.Button(toolbar, text="Save Plots", command=self.save_plots)
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # Help button
        help_btn = ttk.Button(toolbar, text="Help", command=self.show_help)
        help_btn.pack(side=tk.RIGHT, padx=5)
        
    def create_tabs(self):
        """Create tabs for different visualizations"""
        # Protocol Distribution tab
        self.protocol_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.protocol_tab, text='Protocol Distribution')
        
        # Packet Sizes tab
        self.packet_sizes_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.packet_sizes_tab, text='Packet Sizes')
        
        # Traffic Volume tab
        self.traffic_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.traffic_tab, text='Traffic Volume')
        
        # Connection Graph tab
        self.connection_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.connection_tab, text='Connection Graph')
        
        # Top Talkers tab
        self.talkers_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.talkers_tab, text='Top Talkers')
        
        # Transport Protocols tab
        self.transport_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.transport_tab, text='Transport Protocols')
        
    def open_pcap(self):
        """Open and parse a PCAP file"""
        # Ask user to select a PCAP file
        file_path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[
                ("PCAP files", "*.pcap *.pcapng"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        # Update status
        self.status_var.set(f"Loading {os.path.basename(file_path)}...")
        self.root.update_idletasks()
        
        # Load PCAP file
        if self.parser.load_pcap(file_path):
            self.status_var.set(f"Loaded {self.parser.packet_count} packets from {os.path.basename(file_path)}")
            # Generate all plots
            self.refresh_plots()
        else:
            self.status_var.set(f"Failed to load {os.path.basename(file_path)}")
            messagebox.showerror("Error", f"Failed to load PCAP file: {file_path}")
    
    def refresh_plots(self):
        """Refresh all plots"""
        if not self.parser.packets:
            messagebox.showinfo("No Data", "Please open a PCAP file first.")
            return
            
        # Update status
        self.status_var.set("Generating visualizations...")
        self.root.update_idletasks()
        
        # Create and display all plots
        self.display_protocol_distribution()
        self.display_packet_sizes()
        self.display_traffic_volume()
        self.display_connection_graph()
        self.display_top_talkers()
        self.display_transport_protocols()
        
        # Update status
        self.status_var.set(f"Visualizations complete for {self.parser.packet_count} packets")
        
    def display_protocol_distribution(self):
        """Display protocol distribution visualization"""
        # Clear previous plot
        for widget in self.protocol_tab.winfo_children():
            widget.destroy()
            
        # Generate plot
        fig = self.visualizer.plot_protocol_distribution()
        
        if fig:
            # Create canvas for the plot
            canvas = FigureCanvasTkAgg(fig, master=self.protocol_tab)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.protocol_tab)
            toolbar.update()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            # Display message if no data
            label = ttk.Label(self.protocol_tab, text="No protocol data available")
            label.pack(pady=50)
    
    def display_packet_sizes(self):
        """Display packet sizes visualization"""
        # Clear previous plot
        for widget in self.packet_sizes_tab.winfo_children():
            widget.destroy()
            
        # Generate plot
        fig = self.visualizer.plot_packet_sizes_over_time()
        
        if fig:
            # Create canvas for the plot
            canvas = FigureCanvasTkAgg(fig, master=self.packet_sizes_tab)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.packet_sizes_tab)
            toolbar.update()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            # Display message if no data
            label = ttk.Label(self.packet_sizes_tab, text="No packet size data available")
            label.pack(pady=50)
    
    def display_traffic_volume(self):
        """Display traffic volume visualization"""
        # Clear previous plot
        for widget in self.traffic_tab.winfo_children():
            widget.destroy()
            
        # Generate plot
        fig = self.visualizer.plot_traffic_volume()
        
        if fig:
            # Create canvas for the plot
            canvas = FigureCanvasTkAgg(fig, master=self.traffic_tab)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.traffic_tab)
            toolbar.update()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            # Display message if no data
            label = ttk.Label(self.traffic_tab, text="No traffic volume data available")
            label.pack(pady=50)
    
    def display_connection_graph(self):
        """Display connection graph visualization"""
        # Clear previous plot
        for widget in self.connection_tab.winfo_children():
            widget.destroy()
            
        # Generate plot
        fig = self.visualizer.plot_connection_graph()
        
        if fig:
            # Create canvas for the plot
            canvas = FigureCanvasTkAgg(fig, master=self.connection_tab)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.connection_tab)
            toolbar.update()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            # Display message if no data or networkx not available
            label = ttk.Label(self.connection_tab, text="Connection graph not available. \nMake sure networkx is installed.")
            label.pack(pady=50)
    
    def display_top_talkers(self):
        """Display top talkers visualization"""
        # Clear previous plot
        for widget in self.talkers_tab.winfo_children():
            widget.destroy()
            
        # Generate plot
        fig = self.visualizer.plot_top_talkers()
        
        if fig:
            # Create canvas for the plot
            canvas = FigureCanvasTkAgg(fig, master=self.talkers_tab)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.talkers_tab)
            toolbar.update()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            # Display message if no data
            label = ttk.Label(self.talkers_tab, text="No top talkers data available")
            label.pack(pady=50)
    
    def display_transport_protocols(self):
        """Display transport protocols visualization"""
        # Clear previous plot
        for widget in self.transport_tab.winfo_children():
            widget.destroy()
            
        # Generate plot
        fig = self.visualizer.plot_transport_protocol_distribution()
        
        if fig:
            # Create canvas for the plot
            canvas = FigureCanvasTkAgg(fig, master=self.transport_tab)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.transport_tab)
            toolbar.update()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            # Display message if no data
            label = ttk.Label(self.transport_tab, text="No transport protocol data available")
            label.pack(pady=50)
    
    def save_plots(self):
        """Save all plots to a directory"""
        if not self.parser.packets:
            messagebox.showinfo("No Data", "Please open a PCAP file first.")
            return
            
        # Ask user for directory to save plots
        directory = filedialog.askdirectory(title="Select directory to save plots")
        
        if not directory:
            return
            
        # Update status
        self.status_var.set("Saving plots...")
        self.root.update_idletasks()
        
        # Save each plot
        try:
            # Protocol distribution
            fig = self.visualizer.plot_protocol_distribution()
            if fig:
                fig.savefig(os.path.join(directory, "protocol_distribution.png"), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
            # Packet sizes
            fig = self.visualizer.plot_packet_sizes_over_time()
            if fig:
                fig.savefig(os.path.join(directory, "packet_sizes.png"), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
            # Traffic volume
            fig = self.visualizer.plot_traffic_volume()
            if fig:
                fig.savefig(os.path.join(directory, "traffic_volume.png"), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
            # Connection graph
            fig = self.visualizer.plot_connection_graph()
            if fig:
                fig.savefig(os.path.join(directory, "connection_graph.png"), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
            # Top talkers
            fig = self.visualizer.plot_top_talkers()
            if fig:
                fig.savefig(os.path.join(directory, "top_talkers.png"), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
            # Transport protocols
            fig = self.visualizer.plot_transport_protocol_distribution()
            if fig:
                fig.savefig(os.path.join(directory, "transport_protocols.png"), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
            # Update status
            self.status_var.set(f"Plots saved to {directory}")
            messagebox.showinfo("Success", f"All plots saved to {directory}")
            
        except Exception as e:
            logger.error(f"Error saving plots: {str(e)}")
            self.status_var.set("Error saving plots")
            messagebox.showerror("Error", f"Failed to save plots: {str(e)}")
    
    def show_help(self):
        """Show help information"""
        help_text = """
        NetHunter Packet Visualizer

        This tool provides graphical visualizations for network packet analysis to enhance the NetHunter penetration testing experience.

        Usage:
        1. Click "Open PCAP" to select a packet capture file
        2. Navigate through the tabs to view different visualizations
        3. Use "Refresh Plots" to regenerate visualizations
        4. Use "Save Plots" to save all visualizations to a directory

        Tabs:
        - Protocol Distribution: Shows distribution of protocols in the capture
        - Packet Sizes: Shows packet sizes over time
        - Traffic Volume: Shows traffic volume over time
        - Connection Graph: Shows connections between hosts
        - Top Talkers: Shows top talkers (most active IP addresses)
        - Transport Protocols: Shows distribution of transport protocols

        Requirements:
        - Python 3.6+
        - Required packages: matplotlib, pandas, scapy
        - Optional packages: networkx (for connection graphs)

        Created for NetHunter on Samsung Galaxy Tab S7 FE
        """
        
        # Create help window
        help_window = tk.Toplevel(self.root)
        help_window.title("NetHunter Packet Visualizer Help")
        help_window.geometry("600x500")
        help_window.configure(bg=NH_COLORS['background'])
        
        # Add help text
        text = tk.Text(help_window, wrap=tk.WORD, bg=NH_COLORS['background'], fg=NH_COLORS['text'],
                      font=('Helvetica', 10), padx=10, pady=10)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, help_text)
        text.config(state=tk.DISABLED)
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(text)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=text.yview)
        
        # Add close button
        close_btn = ttk.Button(help_window, text="Close", command=help_window.destroy)
        close_btn.pack(pady=10)


def main():
    """Main function to start the application"""
    # Check for required packages
    if not SCAPY_AVAILABLE:
        print("Warning: Scapy not available. PCAP parsing may not work properly.")
        print("Install Scapy with: pip install scapy")
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="NetHunter Packet Visualization Tool")
    parser.add_argument("--pcap", help="PCAP file to open on startup")
    args = parser.parse_args()
    
    # Create Tkinter root window
    root = tk.Tk()
    app = NetHunterPacketVisualizerGUI(root)
    
    # Open PCAP file if specified
    if args.pcap:
        app.parser.load_pcap(args.pcap)
        app.refresh_plots()
    
    # Start the main event loop
    root.mainloop()


if __name__ == "__main__":
    main()