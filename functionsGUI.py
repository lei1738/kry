import csv
import os
import sys
from collections import Counter

import psutil
import pyshark


def save_file(file_content, file_path):
    """
    Saves content to a file.

    :param:
        file_content (bytes): The content to be saved.
        file_path (str): The path where the content will be saved.

    :return:
        None
    """
    with open(file_path, 'wb') as f:
        f.write(file_content)


def open_file(path):
    """
    Opens and reads the content of a file.

    :param:
        path (str): The path of the file to be opened and read.

    :return:
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

    :return:
        str: The root directory path.
    """
    program_path = sys.argv[0]
    root_directory = os.path.dirname(program_path)
    return root_directory


def load_pcap_file(filepath):
    """
    Loads a file and prepares for running.

    :return:
        None
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

    :param:
        interface_name (str): The name of the interface to capture packets from.
        run_time (float): The duration of the capture in seconds.

    :return:
        tuple: A tuple containing the size of the captured file and its content.
    """
    file_name = "capture.pcapng"
    capture = pyshark.LiveCapture(interface=interface_name, output_file=file_name)
    capture.set_debug()
    capture.sniff(timeout=run_time)
    capture_size = os.path.getsize(file_name)
    captured_file = open_file(get_root_folder() + "\\" + file_name)
    return capture_size, captured_file


def get_interfaces():
    """
    Retrieves a list of available network interfaces.

    :return:
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

    :param:
        path (str): The path from which to extract the file name.

    :return:
        str: The extracted file name.
    """
    path_parts = path.split("/")
    file_name = path_parts[-1]
    return file_name

def format_string(string, SIZE, char):
    if len(string) > SIZE:
        return string[:SIZE]
    elif len(string) < SIZE:
        return string + char * (SIZE - len(string))
    else:
        return string

def count_protocols(csv_path):
    """
    Counts the occurrences of each protocol mentioned in a CSV file.

    :param:
        csv_path (str): The path to the input CSV file.

    :return:
        dict: A dictionary containing the count of occurrences of each protocol.
    """
    protocols_count = {}

    # Open the .csv file for reading
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)

        # Skip the header
        next(reader)

        # Iterate through the rows of the .csv file
        for row in reader:
            if row[-1] == '1':
                # Get the protocol used from the current row
                protocol = row[3]
                protocol = protocol + "\t-"
                # Increase the count of the protocol occurrences
                protocols_count[protocol] = protocols_count.get(protocol, 0) + 1

    return protocols_count


def number_of_packets(csv_path):
    """
    Counts the total number of packets in a CSV file.

    :param:
        csv_path (str): The path to the input CSV file.

    :return:
        int: The total number of packets in the CSV file.
    """
    with open(csv_path, 'r', newline='') as csvfile:
        packet_count = sum(1 for _ in csvfile) - 1
    return packet_count


def number_of_encrypted_packets(csv_path):
    """
    Counts the number of encrypted packets in a CSV file.

    :param:
        csv_path (str): The path to the input CSV file.

    :return:
        int: The number of encrypted packets in the CSV file.
    """
    encrypted_packets_count = 0

    # Open the .csv file for reading
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)

        # Skip the header
        next(reader)

        # Iterate through the rows of the .csv file
        for row in reader:
            # Check if the last value in the row is equal to 1
            if row[-1] == '1':
                # Increment the count
                encrypted_packets_count += 1

    return encrypted_packets_count


def src_dst_encrypted_packets(csv_path):
    """
    Extracts unique source-destination pairs of encrypted packets from a CSV file along with their counts.

    :param:
        csv_path (str): The path to the input CSV file.

    :return:
        list: A list containing unique source-destination pairs of encrypted packets along with their counts.
    """
    src_dst = []

    # Open the .csv file for reading
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)

        for row in reader:
            # Check if the last value in the row is equal to 1
            if row[-1] == '1':
                # Increment the count
                if row[13] == '' and row[14] == '':
                    if row[16] == '' and row[17] == '':
                        continue
                    src = row[16]
                    dst = row[17]
                else:
                    src = row[13]
                    dst = row[14]

                src_dst1 = [src, dst]
                src_dst.append(src_dst1)

        src_dst_final = unique_with_count(src_dst)
        src_dst_final = format_src_dst(src_dst_final, False)

    return src_dst_final


def format_src_dst(src_dst_arr, divide): # Divide column Src_Dst into two columns
    """
        Formats source-destination pairs into two columns if specified, otherwise combines them into one column.

        :param:
            src_dst_arr (list): List of source-destination pairs along with their counts.
            divide (bool): If True, divides the source-destination pairs into two separate columns.

        :return:
            list: Formatted source-destination pairs.
    """
    arr = []
    for row in src_dst_arr:
        src = row[0][0]
        dst = row[0][1]
        count = row[1]
        if divide:
            count_src_dst = [count,src,dst]
        else:
            count_src_dst = [f"{count}\t-", f"{src}   -   {dst}"]
        arr.append(count_src_dst)
    return arr


def unique_with_count(input_list):
    """
    Counts the occurrences of unique elements in a list and returns a list of unique elements with their counts.

    :param:
        input_list (list): The input list containing elements.

    :return:
        list: A list containing unique elements along with their counts of occurrences.
    """
    # Convert inner lists to immutable tuples so they can be used as keys in Counter
    input_list_tuples = [tuple(inner_list) for inner_list in input_list]

    # Create a dictionary with the count of occurrences of each element
    counts = Counter(input_list_tuples)

    # Create a new list for unique elements with their count of occurrences
    unique_list = [[list(item), counts[item]] for item in set(input_list_tuples)]

    return unique_list


def encrypted_packet_size(csv_path):
    """
       Extracts and counts the sizes of encrypted packets from a CSV file.

       :param:
           csv_path (str): The path to the input CSV file.

       :return:
           list: A list containing unique encrypted packet sizes along with their counts.
    """
    packet_sizes = []
    # Open the .csv file for reading
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)

        for row in reader:
            # Check if the last value in the row is equal to 1
            if row[-1] == '1':
                # Increment the count
                if row[15] != '':
                    size = row[15]
                else:
                    continue

                packet_sizes1 = [size]
                packet_sizes.append(packet_sizes1)

        packet_sizes_final = unique_with_count(packet_sizes)
        packet_sizes_final = fix_packet_size_arr(packet_sizes_final)

    return packet_sizes_final

def fix_packet_size_arr(packet_size_arr):
    """
        Formats packet size array by trimming decimals and appending a character.

        :param:
            packet_size_arr (list): List of packet sizes along with their counts.

        :return:
            list: Formatted packet size array.
    """
    arr1 = []
    for row in packet_size_arr:
        size = row[0][0]
        size = trim_decimals(str(size)) + "\t-"
        count = row[1]
        new_row = [size, count]
        arr1.append(new_row)
    return arr1

def trim_decimals(s):
    """
    Trims decimals from a string if present.

    :param:
        s (str): The string to trim decimals from.

    :return:
        str: The trimmed string.
    """
    if s.endswith(".0"):
        return s[:-2]
    return s

def could_be_encrypted(csv_path):
    pass
