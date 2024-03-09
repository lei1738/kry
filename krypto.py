from scapy.all import *
import pyshark
import os
from enum import Enum


class Unit(Enum):
    GB = 1073741824
    MB = 1048576
    KB = 1024
    B = 1


# PcapReader creates a generator
# it does NOT load the complete file in memory
# https://cylab.be/blog/245/network-traffic-analysis-with-python-scapy-and-some-machine-learning?fbclid=IwAR2qkYFQ8GuFSaAM0H3GjHD8VylCplOleQvJ8bxSsr5RdUjaMgbl1ZLuuLA&accept-cookies=1
# packets = PcapReader("capture.pcap")
#
# # Loop through the packets
# for packet in packets:
#     print(packet.show())


# ********USER ACTION REQUIRED*********#
# Please change interfaceId/name for below line as per your system.

INTERFACE_NAME = "Ethernet"
capture_size = 0


# Functions

def capture_packets(time):
    """Capture packets from the specified interface for the given time duration."""
    file_name = "capture.pcapng"
    capture = pyshark.LiveCapture(interface=INTERFACE_NAME, output_file=file_name)
    capture.set_debug()
    capture.sniff(timeout=time)
    capture_size = os.path.getsize(file_name)
    return capture_size


# Main

print(f"Selected Interface: {INTERFACE_NAME}\n")

time = int(input("Enter the traffic capture time (in seconds, at least 20 sec): \n"))
print(Unit.GB.value - 10)

if time < 20:
    print("Time must be over 20 sec.\n")
else:
    print(f"\nCapture time is: {time} seconds\n")

    capture_size = capture_packets(time + 10)

# Conevert to GB
if capture_size >= Unit.GB.value:
    capture_size = capture_size / Unit.GB.value
    print(f"Total Packet size captured is => {capture_size:.2f}GB")
# Conevert to MB
elif capture_size >= Unit.MB.value:
    capture_size = capture_size / Unit.MB.value
    print(f"Total Packet size captured is => {capture_size:.2f}MB")
# Conevert to KB
elif capture_size >= Unit.KB.value:
    capture_size = capture_size / Unit.KB.value
    print(f"Total Packet size captured is => {capture_size:.2f}KB")
else:
    capture_size = capture_size / Unit.B.value
    print(f"Total Packet size captured is => {capture_size:.2f}B")

packet_count = 0

for pkt in PcapReader('capture.pcapng'):
    packet_count += 1

print(f"Total Packet count captured is => {packet_count}")
