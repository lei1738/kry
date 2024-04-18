import os
import pandas as pd
import random

# !!! SMAZAT POSKOZENE SOUBORY NONVPN_SCP_LONG_CAPTURE1 A VPN_SKYPE_CHAT_CAPTURE6 !!!

def deli(csv_name):
    df = pd.read_csv(csv_name)
    df.pop("raw")
    df.pop("text")
    df.to_csv(csv_name, index=False)

def hash_string_values(csv_name):
    df = pd.read_csv(csv_name)
    biglist = ["frame.protocols", "_ws.col.protocol", "ip.id", "ip.flags", "ip.flags.rb", "ip.flags.df", "ip.flags.mf",
               "ip.checksum",
               "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.flags", "tcp.flags.fin", "tcp.flags.syn",
               "tcp.flags.reset",
               "tcp.flags.push", "tcp.flags.ack", "tcp.flags.urg", "tcp.flags.cwr", "tcp.checksum", "dns.flags",
               "dns.flags.recdesired",
               "dns.flags.recavail", "dns.flags.authenticated", "dns.qry.class", "dns.resp.class", "http.connection",
               "http.request.method",
               "http.request.version", "http.request.uri", "http.response.version", "http.user_agent",
               "tls.handshake.version",
               "ssh.host_key.type", "ssh.host_sig.type", "ssh.protocol", "rdp.negReq.selectedProtocol", "data"]
    finallist = []
    for col in df.columns:
        finallist.append(col)
    s = set(finallist) - set(biglist)
    for l in list(s):
        thislist = df[l].tolist()
        new_values = [hash(hodnota) for hodnota in thislist]
        df[l] = new_values

    df.to_csv(csv_name, index=False)


def merge():
    '''directory = 'csv'
    df_csv_concat = pd.concat([pd.read_csv("C:\\Users\\vasek\\OneDrive\\Plocha\\programování\\KRY-projekt\\kry\\csv\\nonvpn_rdp_capture_5pcap.csv")], ignore_index=True)
    #print(df_csv_concat)
    for file in os.listdir(directory)[1:5]:
        print(file)
        df_csv_concat = df_csv_concat + pd.concat([pd.read_csv("csv\\"+file)], ignore_index=True)
    df_csv_concat.to_csv("big2.csv", index=False)'''

    CHUNK_SIZE = 50000
    csv_file_list = os.listdir(directory)
    output_file = "output_neuron.csv"

    first_one = True
    for csv_file_name in csv_file_list:

        if not first_one: # if it is not the first csv file then skip the header row (row 0) of that file
            skip_row = [0]
        else:
            skip_row = []

        chunk_container = pd.read_csv('csv\\' + csv_file_name, chunksize=CHUNK_SIZE, skiprows = skip_row)
        for chunk in chunk_container:
            chunk.to_csv(output_file, mode="a", index=False)
        first_one = False

def convert_pcap_to_csv(pcap_file, csv_name):
    cmd = "tshark -r " + pcap_file + (" -T fields -e frame.time_relative -e frame.protocols -e ip.version "
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
                                      "-e dhcp.hops -e dhcp.type -e rdp.negReq.selectedProtocol -e raw -e data -e text -E header=y -E separator=, -E occurrence=f > csv\\" + csv_name)
    os.system(cmd)


def addColumnForVPN(csv_name):
    df = pd.read_csv(csv_name)
    thislist = len(df['frame.time_relative'].tolist())
    new_values = [1]*thislist
    df['encrypted'] = new_values

    df.to_csv(csv_name, index=False)

def addColumnForNonVPN(csv_name):
    df = pd.read_csv(csv_name)
    thislist = len(df['frame.time_relative'].tolist())
    new_values = [0]*thislist
    df['encrypted'] = new_values

    df.to_csv(csv_name, index=False)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    directory = 'csv'
    #csv = ''
    '''for filename in os.listdir(directory):
        #csv = filename + '.csv'
        file = 'csv\\' + filename
        print(file)
        #convert_pcap_to_csv(file, csv)
        #addColumnForVPN(file)
        deli(file)'''
    #merge()

    #list random
    # listNum = random.sample(range(1,157), 156)
    # i=0
    # for filename in os.listdir(directory):
    #     x = "csv\\" + filename
    #     z = filename.join((str(listNum[i]),filename))
    #     y = "csv\\" + z
    #     os.rename(x, y)
    #     i+=1

    '''listNum = random.sample(range(1, 157), 156)
    i = 0
    directory = 'csv'
    for filename in os.listdir(directory):
        x = "csv\\" + filename
        z = filename.join((str(listNum[i]), filename))
        y = "csv\\" + z.replace(".", "", 1)
        os.rename(x, y)
        i += 1'''

    '''for filename in os.listdir(directory):
        x = "csv\\" + filename
        z = "csv\\" + filename[3:]
        os.rename(x, z)'''
    '''for filename in os.listdir(directory):
        #df = pd.read_csv('csv\\' + filename)
        print(filename)
        hash_string_values('csv\\' + filename)
        #df.fillna(0, inplace=True)
        #df.to_csv('csv' + filename, index=False)'''

