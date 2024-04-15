import os

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
                                      "-e dhcpv6.auth.protocol -e dhcpv6.hopcount -E separator=, -E occurrence=f > csv\\" + csv_name)
    os.system(cmd)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    directory = 'VNAT_release_1'
    csv = ''
    for filename in os.listdir(directory):
        csv = filename + '.csv'
        filename = 'VNAT_release_1\\' + filename
        convert_pcap_to_csv(filename, csv)
