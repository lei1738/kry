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


def capture_packet(time):
    file = "capture.pcapng"
    output = open(file, "w")
    capture = pyshark.LiveCapture(interface=INTERFACE_NAME, output_file=file)
    capture.set_debug()
    capture.sniff(timeout=time)
    output.close()
    return os.path.getsize(file)

# Step1 -> Entry to code

print("****Hope you have added correct interface name into this python file****\n")
time = int(input("How long(sec) to capture traffic? [Value should be more than 20 sec]\n"))

if time < 20:
    print("Timeout must be over 20 seconds.\n")
else:
    print("\nCapture time is: ", time, "sec for each interface.\n\n ....Please wait....")

# Step2 -> Functions
capture_size = capture_packet(time + 10)  # 2. Start capturing packets on provided interface

if capture_size >= 1073741824:
    print("|---Total Packet size captured is => ", '{0:.2f}'.format(capture_size / (1024 * 1024 * 1024)), "GB ---|")
elif capture_size >= 1048576:
    print("|---Total Packet size captured is => ", '{0:.2f}'.format(capture_size / (1024 * 1024)), "MB ---|")
elif capture_size >= 1024:
    print("|---Total Packet size captured is => ", '{0:.2f}'.format(capture_size / 1024), "KB ---|")
else:
    print("|---Total Packet size captured is => ", capture_size, "bytes ---|")
