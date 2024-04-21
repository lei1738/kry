import os

import pandas as pd
from sklearn.utils import shuffle


def shuffleCSV(csv_name, new_csv=""):
    """
    Shuffles the rows of a CSV file.

    :param:
        csv_name (str): Path to the CSV file to shuffle.
        new_csv (str, optional): Path to the new shuffled CSV file.

    :return:
        None
    """
    df = pd.read_csv(csv_name)
    df = shuffle(df)
    df.to_csv(csv_name if new_csv == "" else new_csv, chunksize=50000)


def deleteColumn(csv_name, column_name, new_csv=""):
    """
    Deletes a column from a CSV file.

    :param:
        csv_name (str): Path to the CSV file.
        column_name (str): Path to the column to delete.
        new_csv (str, optional): Path to the new CSV file.

    :return:
        None
    """
    df = pd.read_csv(csv_name)
    df.pop(column_name)
    df.to_csv(csv_name if new_csv == "" else new_csv, index=False)


def addColumn(csv_name, column_name, values, new_csv=""):
    """
    Adds a new column with specified values to a CSV file.

    :param:
        csv_name (str): Path to the CSV file.
        column_name (str): Path to the new column.
        values (list): The values to be added in the new column.
        new_csv (str, optional): Path to the new CSV file.

    :return:
        None
    """
    df = pd.read_csv(csv_name)
    df[column_name] = values
    df.to_csv(csv_name if new_csv == "" else new_csv, index=False)


def hashValues(csv_name, new_csv=""):
    """
    Hashes the values of all columns in a CSV file.

    :param:
        csv_name (str): Path to the CSV file.
        new_csv (str, optional): Path to the new CSV file.

    :return:
        None
    """
    df = pd.read_csv(csv_name)

    for l in list(df.columns):
        thislist = df[l].tolist()
        new_values = [hash(val) for val in thislist]
        df[l] = new_values

    df.to_csv(csv_name if new_csv == "" else new_csv, index=False)


def merge(directory):
    """
    Merges multiple CSV files in a directory into a single CSV file.

    :param:
        directory (str): The directory containing CSV files to merge.

    :return:
        None
    """
    CHUNK_SIZE = 50000
    csv_file_list = os.listdir(directory)
    output_file = "merged_output.csv"

    first_one = True
    for csv_file_name in csv_file_list:
        if not first_one:
            skip_row = [0]
        else:
            skip_row = []

        chunk_container = pd.read_csv(directory + '\\' + csv_file_name, chunksize=CHUNK_SIZE, skiprows=skip_row)
        for chunk in chunk_container:
            chunk.to_csv(output_file, mode="a", index=False)
        first_one = False


def convertPcapToCSV(pcap_file, csv_name):
    """
    Converts a PCAP file to a CSV file using tshark.

    :param:
        pcap_file (str): Path to the PCAP file.
        csv_name (str): Path to the resulting CSV file.

    :return:
        None
    """
    cmd = "tshark -r " + pcap_file + (" -T fields -e frame.time_relative -e frame.protocols -e ip.version "
                                      "-e _ws.col.Protocol -e ip.hdr_len -e ip.id -e ip.flags -e ip.flags.rb -e ip.flags.df "
                                      "-e ip.flags.mf -e ip.ttl -e ip.proto -e ip.checksum -e ip.src -e ip.dst -e ip.len "
                                      "-e ipv6.src -e ipv6.dst -e tcp.analysis -e tcp.port -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack "
                                      "-e tcp.hdr_len -e tcp.flags -e tcp.flags.fin -e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push "
                                      "-e tcp.flags.ack -e tcp.flags.urg -e tcp.flags.cwr -e tcp.window_size -e tcp.checksum "
                                      "-e icmpv6.code -e icmpv6.type -e udp.length -e udp.port -e icmp.code "
                                      "-e icmp.type -e dns.flags -e dns.flags.recdesired -e dns.flags.recavail -e dns.flags.authenticated -e dns.qry.type "
                                      "-e dns.qry.class -e dns.resp.type -e dns.resp.class -e dns.resp.ttl -e http.connection "
                                      "-e http.request.method -e http.request.version -e http.request.uri -e http.response.version "
                                      "-e http.response.code -e http.user_agent -e tls.handshake -e tls.handshake.type -e tls.handshake.version "
                                      "-e tls.handshake.ciphersuites -e ssh.host_key.type -e ssh.host_sig.type -e ssh.packet_length -e ssh.protocol "
                                      "-e dhcp.hops -e dhcp.type -e rdp.negReq.selectedProtocol -e data -E header=y -E separator=, -E occurrence=f > " + csv_name)
    os.system(cmd)


def renamePcapToCSV(csv_name, directory):
    """
    Renames a CSV file in a directory.

    :param:
        csv_name (str): Path to the CSV file.
        directory (str): The directory containing the CSV file.

    :return:
        None
    """
    original = directory + "\\" + csv_name
    copy = "".join(csv_name)
    renamed = directory + "\\" + copy.replace(".", "", 1)
    os.rename(original, renamed)


def addEncrypted(csv_name, vpn):
    """
    Adds a new column 'encrypted' to a CSV file indicating VPN usage.

    :param:
        csv_name (str): Path to the CSV file.
        vpn (bool): True if VPN was used, False otherwise.

    :return:
        None
    """
    df = pd.read_csv(csv_name)
    thislist = len(df['frame.time_relative'].tolist())
    new_values = [1] * thislist if vpn else [0] * thislist
    df['encrypted'] = new_values
    df.to_csv(csv_name, index=False)
