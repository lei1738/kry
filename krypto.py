from scapy.all import *
import pyshark
import os

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

INTERFACE_NAME = "Wi-Fi"
capture_size = 0

# Functions

def capture_packets(time):
    """Capture packets from the specified interface for the given time duration."""
    file_name = "capture.pcap"
    capture = pyshark.LiveCapture(interface=INTERFACE_NAME, output_file=file_name)
    capture.set_debug()
    capture.sniff(timeout=time)
    capture_size = os.path.getsize(file_name)
    return capture_size

# Main

print(f"Selected Interface: {INTERFACE_NAME}\n")

time = int(input("Enter the traffic capture time (in seconds, at least 20 sec): \n"))

if time < 20:
    print("Time must be over 20 sec.\n")
else:
    print(f"\nCapture time is: {time} seconds\n")

    capture_size = capture_packets(time + 10)

# Conevert to GB
    if capture_size >= 1073741824:
        print(f"|---Total Packet size captured is => {capture_size / (1024 * 1024 * 1024):.2f} GB ---|")
# Conevert to MB
    elif capture_size >= 1048576:
        print(f"|---Total Packet size captured is => {capture_size / (1024 * 1024):.2f} MB ---|")
# Conevert to KB
    elif capture_size >= 1024:
        print(f"Total Packet size captured is => {capture_size / 1024:.2f} KB ---|")
    else:
        print(f"|---Total Packet size captured is => {capture_size} bytes ---|")



