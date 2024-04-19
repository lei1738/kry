import pandas as pd
import scapy.utils
from scapy.all import *
import pyshark
import os
from enum import Enum
import convert_pcap_to_csv
import neuron
import neuron3

class Unit(Enum):
    GB = 1073741824
    MB = 1048576
    KB = 1024
    B = 1

# Functions
def removeheader(csv_name):
    df = pd.read_csv(csv_name)
    print("Delka: "+str(len(df.columns)))
    #df.to_csv("final_output.csv",header=None, index=False)
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
    cmd = "tshark -r " + pcap_file + (" -T fields -e frame.time_relative -e frame.len -e frame.protocols -e frame.len -e ip.version "
                                      "-e _ws.col.Protocol -e ip.hdr_len -e ip.tos -e ip.id -e ip.flags -e ip.flags.rb -e ip.flags.df "
                                      "-e ip.flags.mf -e ip.frag_offset -e ip.ttl -e ip.proto -e ip.checksum -e ip.src -e ip.dst -e ip.len "
                                      "-e ip.dsfield -e ip.geoip.dst_country -e ip.geoip.dst_city -e ip.geoip.src_country -e ip.geoip.src_city "
                                      "-e tcp.analysis -e tcp.len -e tcp.port -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len"
                                      " -e tcp.hdr_len -e tcp.flags -e tcp.flags.fin -e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push "
                                      "-e tcp.flags.ack -e tcp.flags.urg -e tcp.flags.cwr -e tcp.window_size -e tcp.checksum "
                                      "-e tcp.urgent_pointer -e tcp.options.mss_val -e udp.length -e udp.port -e icmp.code -e icmp.length "
                                      "-e icmp.type -e icmp.pref_level -e icmpv6.code -e icmpv6.length -e icmpv6.type -e dns.flags "
                                      "-e dns.flags.recdesired -e dns.flags.recavail -e dns.flags.authenticated -e dns.qry.type "
                                      "-e dns.qry.class -e dns.resp.type -e dns.resp.class -e dns.resp.ttl -e http.connection "
                                      "-e http.content_encoding -e http.content_length -e http.content_type -e http.location "
                                      "-e http.request.method -e http.request.version -e http.request.uri -e http.response.version "
                                      "-e http.response.code -e http.tls_port -e http.user_agent -e http.www_authenticate -e tls.alert_message "
                                      "-e tls.ech.cipher_suite -e tls.esni.suite -e tls.handshake -e tls.handshake.type "
                                      "-e tls.handshake.version -e tls.handshake.ciphersuites -e tls.ssl2.handshake.type "
                                      "-e tls.ssl2.handshake.cipherspec -e sip.auth -e sip.auth.algorithm -e sip.Geolocation "
                                      "-e sip.MIME-Version -e sip.Via.transport -e sip.Via.ttl -e ssh.host_key.type -e ssh.host_sig.type "
                                      "-e ssh.packet_length -e ssh.protocol -e dhcp.hops -e dhcp.type -e dhcpv6.auth.algorithm "
                                      "-e dhcpv6.auth.protocol -e dhcpv6.hopcount -e rdp.action -e rdp.bVersion -e rdp.bandwidth.headerlen "
                                      "-e rdp.bandwidth.reqtype -e rdp.bandwidth.resptype -e rdp.bandwidth.typeid -e rdp.client.address "
                                      "-e rdp.connectionType -e rdp.domain -e rdp.encryptionLevel -e rdp.encryptionMethod -e rdp.entrySize "
                                      "-e rdp.fastpath.eventheader -e rdp.header.length -e rdp.header.type -e rdp.heartbeat.period "
                                      "-e rdp.length -e rdp.negReq.selectedProtocol -e rdp.rdstls.version -e rdp.networkcharacteristics.averagertt "
                                      "-e rdp.targetUser -e rdp.totalLength -e rsync.hdr_magic -e rsync.hdr_version -e sftp.length -e sftp.name_count "
                                      "-e sftp.packet_length -e sftp.packet_type -e sftp.status -e sftp.version -e rtp.block-length -e rtp.hdr_ext "
                                      "-e rtp.p_type -e rtp.version -E header=y -E separator=, -E occurrence=f  > traffic.csv")
    os.system(cmd)


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
    INTERFACE_NAME = "WiFi"
    '''print(f"Selected Interface: {INTERFACE_NAME}\n")

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

    neuron.neuronka("traffic.csv") #volani z jinyho souboru'''

    #removeheader('csv\\1nonvpn_skype-chat_capture21pcap.csv')
    #neuron3.neuronka('shuffle_neuron_output.csv')
    neuron3.vyhodnoceni('1vpn_ssh_capture1pcap.csv')

