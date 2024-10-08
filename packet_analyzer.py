# Import necessary libraries
from scapy.all import *
import time
import pandas as pd
from datetime import datetime
from scapy.all import get_if_list

# List to store the captured packet details
packet_list = []

# Function to handle each captured packet
def packet_callback(packet):
    # Check if the packet has the IP layer
    if packet.haslayer(IP):
        # Get the timestamp, source IP, destination IP, and protocol
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        packet_size = len(packet)

        # Add packet info to list
        packet_list.append({
            'Timestamp': timestamp,
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': proto,
            'Packet Size': packet_size
        })

        # Print packet info
        print(f"[{timestamp}] {src_ip} -> {dst_ip} | Protocol: {proto} | Size: {packet_size} bytes")


# Function to start capturing packets
def start_packet_capture(interface):
    print(f"Starting packet capture on {interface}... Press Ctrl+C to stop.")
    try:
        # Capture packets until interrupted
        sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
        # Stop capturing and log the packet list to a CSV file
        save_packets_to_csv()


# Function to save captured packets to a CSV file
def save_packets_to_csv():
    if packet_list:
        df = pd.DataFrame(packet_list)
        filename = f"packet_log_{time.strftime('%Y%m%d-%H%M%S')}.csv"
        df.to_csv(filename, index=False)
        print(f"Packet capture log saved to {filename}")
    else:
        print("No packets captured.")

# Function to detect and return the interface for Wi-Fi or LAN
def get_interface():
    interfaces = get_if_list()

    # Windows interfaces typically have names like these
    wifi_interfaces = [i for i in interfaces if "Wi-Fi" in i or "wlan" in i]
    lan_interfaces = [i for i in interfaces if "Ethernet" in i or "eth" in i]

    # Check if Wi-Fi interface exists
    if wifi_interfaces:
        return wifi_interfaces[0]  # Return the first detected Wi-Fi interface

    # Check if LAN interface exists
    elif lan_interfaces:
        return lan_interfaces[0]  # Return the first detected LAN interface

    else:
        print("No suitable network interface found. Please check your network connections.")
        return None


if __name__ == "__main__":
    # Automatically detect Wi-Fi or LAN interface
    interface = get_interface()

    if interface:
        # Start capturing packets on the detected interface
        start_packet_capture(interface)
    else:
        print("Could not find a valid network interface to capture packets.")
