from Functions import *
CSV_RELATIVE_FILEPATH = 'temp\\' + 'temp.csv'

if __name__ == "__main__":
    protocols_count = count_protocols(CSV_RELATIVE_FILEPATH)
    print(protocols_count)
    number_of_encrypted_packets = number_of_encrypted_packets(CSV_RELATIVE_FILEPATH)
    print(number_of_encrypted_packets)
    number_of_packets = number_of_packets(CSV_RELATIVE_FILEPATH)
    print(number_of_packets)
    percentage_of_packets_encrypted = number_of_encrypted_packets/number_of_packets * 100
    print(f"{percentage_of_packets_encrypted:.2f}%")