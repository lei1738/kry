import os
import pandas as pd
import random

# !!! SMAZAT POSKOZENE SOUBORY NONVPN_SCP_LONG_CAPTURE1 A VPN_SKYPE_CHAT_CAPTURE6 !!!
def convert_pcap_to_csv(pcap_file, csv_name):
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
                                      "-e rtp.p_type -e rtp.version -E header=y -E separator=, -E occurrence=f > csv\\" + csv_name)
    os.system(cmd)


def addColumn(csv_name):
    df = pd.read_csv(csv_name)
    thislist = len(df['ip.version'].tolist())

    new_values = []
    for i in range(thislist):
        new_values.append(random.randint(0, 1)) #nebude random

    df['encrypted'] = new_values

    df.to_csv(csv_name, index=False)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    directory = 'VNAT_release_1'
    csv = ''
    for filename in os.listdir(directory):
        csv = filename + '.csv'
        filename = 'VNAT_release_1\\' + filename
        convert_pcap_to_csv(filename, csv)
