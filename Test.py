from tabulate import tabulate

from Functions import *

CSV_RELATIVE_FILEPATH = 'temp\\' + 'temp.csv'


def write_table_packet_size(packet_sizes):
    packets_table = tabulate(packet_sizes, headers=["Packet size", "Occurrence"], tablefmt="plain", numalign="right")
    print(packets_table)


def write_table_src_dst(src_dst):
    src_dst_table = tabulate(src_dst, headers=["Src", "Dst", "Occurrence"], tablefmt="plain", numalign="right")
    print(src_dst_table)


if __name__ == "__main__":
    protocols_count = count_protocols(CSV_RELATIVE_FILEPATH)
    print(protocols_count)

    number_of_encrypted_packets = number_of_encrypted_packets(CSV_RELATIVE_FILEPATH)
    print(number_of_encrypted_packets)

    number_of_packets = number_of_packets(CSV_RELATIVE_FILEPATH)
    print(number_of_packets)

    percentage_of_packets_encrypted = number_of_encrypted_packets/number_of_packets * 100
    print(f"{percentage_of_packets_encrypted:.2f}%")

    src_dst = src_dst_encrypted_packets(CSV_RELATIVE_FILEPATH)
    print(src_dst)

    packet_size = encrypted_packet_size(CSV_RELATIVE_FILEPATH)
    print(packet_size)
    write_table_packet_size(packet_size)

    write_table_src_dst(src_dst)

