import os
import sys

import psutil
import pyshark

import csv


def save_file(file_content, file_path):
    """
    Saves content to a file.

    Args:
        file_content (bytes): The content to be saved.
        file_path (str): The path where the content will be saved.
    """
    with open(file_path, 'wb') as f:
        f.write(file_content)


def open_file(path):
    """
    Opens and reads the content of a file.

    Args:
        path (str): The path of the file to be opened and read.

    Returns:
        bytes: The content of the file as a byte string.
            None if the file is not found or an error occurs.
    """
    try:
        with open(path, "rb") as file:
            file_content = file.read()
        return file_content
    except FileNotFoundError:
        print(f"File {path} not found.")
        return None
    except Exception as e:
        print(f"Error occurs while reading the file: {e}")
        return None


def get_root_folder():
    """
    Gets the root directory of the program.

    Returns:
        str: The root directory path.
    """
    program_path = sys.argv[0]
    root_directory = os.path.dirname(program_path)
    return root_directory


def load_pcap_file(filepath):
    """
    Loads a file and prepares for running.

    """
    file_name, file_extension = os.path.splitext(filepath)
    if file_extension.lower() == ".pcap" or file_extension.lower() == ".pcapng":
        return open_file(filepath)
    else:
        print("Wrong file type!")
        return None


def capture_packets(interface_name, run_time):
    """
    Capture packets from the specified interface for the given time duration.

    Args:
        interface_name (str): The name of the interface to capture packets from.
        run_time (float): The duration of the capture in seconds.

    Returns:
        tuple: A tuple containing the size of the captured file and its content.
    """
    file_name = "capture.pcapng"
    capture = pyshark.LiveCapture(interface=interface_name, output_file=file_name)
    capture.set_debug()
    capture.sniff(timeout=run_time)
    capture_size = os.path.getsize(file_name)
    print("successfully captured")
    captured_file = open_file(get_root_folder() + "\\" + file_name)
    print("successfully opened")
    return capture_size, captured_file


def get_interfaces():
    """
    Retrieves a list of available network interfaces.

    Returns:
        list: A list of interface names.
    """
    interfaces = psutil.net_if_addrs()
    inters = []
    for interface_name, addresses in interfaces.items():
        inters.append(interface_name)
    return inters


def path_formatted(path):
    """
    Extracts the file name from a given path.

    Args:
        path (str): The path from which to extract the file name.

    Returns:
        str: The extracted file name.
    """
    path_parts = path.split("/")
    file_name = path_parts[-1]
    return file_name


def convert_pcap_to_csv1(pcap_relative_path, csv_relative_path):
    cmd = "tshark -r " + pcap_relative_path + (" -T fields -e frame.time_relative -e frame.protocols -e ip.version "
                                               "-e _ws.col.Protocol -e ip.hdr_len -e ip.id -e ip.flags -e ip.flags.rb -e ip.flags.df "
                                               "-e ip.flags.mf -e ip.ttl -e ip.proto -e ip.checksum -e ip.src -e ip.dst -e ip.len "
                                               "-e ipv6.src -e ipv6.dst -e tcp.analysis -e tcp.port -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack "
                                               "-e tcp.hdr_len -e tcp.flags -e tcp.flags.fin -e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push "
                                               "-e tcp.flags.ack -e tcp.flags.urg -e tcp.flags.cwr -e tcp.window_size -e tcp.checksum "
                                               "-e icmp.type -e icmpv6.code -e icmpv6.type -e udp.length -e udp.port -e icmp.code "
                                               "-e icmp.type -e dns.flags -e dns.flags.recdesired -e dns.flags.recavail -e dns.flags.authenticated -e dns.qry.type "
                                               "-e dns.qry.class -e dns.resp.type -e dns.resp.class -e dns.resp.ttl -e http.connection "
                                               "-e http.request.method -e http.request.version -e http.request.uri -e http.response.version "
                                               "-e http.response.code -e http.user_agent -e tls.handshake -e tls.handshake.type -e tls.handshake.version "
                                               "-e tls.handshake.ciphersuites -e ssh.host_key.type -e ssh.host_sig.type -e ssh.packet_length -e ssh.protocol "
                                               "-e dhcp.hops -e dhcp.type -e rdp.negReq.selectedProtocol -e raw -e data -e text -E header=y -E separator=, -E occurrence=f > " + csv_relative_path)
    os.system(cmd)

def count_protocols(csv_path):
    protocols_count = {}

    # Otevření .csv souboru pro čtení
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)

        # Přeskočení hlavičky
        next(reader)

        # Procházení řádků .csv souboru
        for row in reader:
            if row[-1] == '1':
                # Získání použitého protokolu z daného řádku
                protocol = row[3]


                # Zvýšení počtu výskytů daného protokolu
                protocols_count[protocol] = protocols_count.get(protocol, 0) + 1

    return protocols_count


def number_of_packets(csv_path):
    with open(csv_path, 'r', newline='') as csvfile:
        packet_count = sum(1 for _ in csvfile)-1
    return packet_count

def number_of_encrypted_packets(csv_path):
    encrypted_packets_count = 0

    # Otevření .csv souboru pro čtení
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)

        # Přeskočení hlavičky
        next(reader)

        # Procházení řádků .csv souboru
        for row in reader:
            # Kontrola, zda je poslední hodnota v řádku rovna 1
            if row[-1] == '1':
                # Inkrementace počtu záznamů
                encrypted_packets_count += 1

    return encrypted_packets_count


