import scapy.utils
from scapy.all import *
import pyshark
import os
from enum import Enum

class Unit(Enum):
    GB = 1073741824
    MB = 1048576
    KB = 1024
    B = 1

# Functions
def capture_packets(time):
    """Capture packets from the specified interface for the given time duration."""
    file_name = "capture.pcapng"
    capture = pyshark.LiveCapture(interface=INTERFACE_NAME, output_file=file_name)
    capture.set_debug()
    capture.sniff(timeout=time)
    capture_size = os.path.getsize(file_name)
    return capture_size

def convert_size(capture_size):
    # Convert to GB
    if capture_size >= Unit.GB.value:
        final_size = capture_size / Unit.GB.value
        return (f"Total Packet size captured is => {final_size:.2f}GB")
    # Convert to MB
    elif capture_size >= Unit.MB.value:
        final_size = capture_size / Unit.MB.value
        return (f"Total Packet size captured is => {final_size:.2f}MB")
    # Convert to KB
    elif capture_size >= Unit.KB.value:
        final_size = capture_size / Unit.KB.value
        return (f"Total Packet size captured is => {final_size:.2f}KB")
    else:
        final_size = capture_size / Unit.B.value
        return (f"Total Packet size captured is => {final_size:.2f}B")


def convert_pcap_to_csv(pcap_file):
    cmd = "tshark -r " + pcap_file + " -T fields -e ip.src -e frame.len -e  ip.proto -E separator=, -E occurrence=f > traffic.csv"
    os.system(cmd)
    #tshark - r C:\Users\vasek\OneDrive\Plocha\programování\KRY - projekt\kry\capture.pcapng - T fields - e ip.src - e frame.len - e ip.proto - E separator =, -E occurrence = f > C:\Users\vasek\OneDrive\Plocha\programování\KRY - projekt\traffic.csv

def process_packets(pcap_file):
    # Dictionary to store the count of occurrences for each protocol
    protocol_count = {}

    # Read the pcap file using Scapy
    pcap_data = rdpcap(pcap_file)

    # Extract sessions from the pcap data
    sessions = pcap_data.sessions()

    for session in sessions:
        for packet in sessions[session]:
            for i in range(len(packet.layers())):
                layer = packet.getlayer(i)      # Get the current layer
                protocol = layer.name       # Get the name of the protocol for the current layer
                # Count the number of occurrences for each protocol
                if protocol not in protocol_count:
                    protocol_count[protocol] = 1
                else:
                    protocol_count[protocol] += 1

    # Sort the dictionary in descending order based on the count of occurrences
    protocol_count = dict(sorted(protocol_count.items(), key=lambda item: item[1], reverse=True))

    # Print the output
    for protocol in protocol_count:
        print(f'{protocol_count[protocol]} packets have "{protocol}"')

# Main
if __name__ == "__main__":
    INTERFACE_NAME = "Wifi"
    print(f"Selected Interface: {INTERFACE_NAME}\n")

    while True:
        time = int(input("Enter the traffic capture time (in seconds, at least 20 sec): \n"))
        if time < 20:
            print("Time must be over 20 sec.\n")
        else:
            break

    print(f"\nCapture time is: {time} seconds\n")
    capture_size = capture_packets(time)
    print(convert_size(capture_size))

    packet_count = 0
    for pkt in PcapReader('capture.pcapng'):
        packet_count += 1

    print(f"Total Packet count captured is => {packet_count}")

    process_packets('capture.pcapng')
    convert_pcap_to_csv('capture.pcapng')

