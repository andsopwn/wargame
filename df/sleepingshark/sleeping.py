from pwn import *
import dpkt
import datetime
from dpkt.compat import compat_ord
import urllib

def analyze_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    flag = list()
    for i in range(39):
        flag.append('X')
    post_sent = False
    payload = ''
    request_time = 0
    response_time = 0
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:


        eth = dpkt.ethernet.Ethernet(buf)
        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue
        ip = eth.data
        tcp = ip.data
        if not post_sent and tcp.dport == 80 and len(tcp.data) > 0:
            # Print out the timestamp in UTC
            time = datetime.datetime.utcfromtimestamp(timestamp)
            print('Timestamp: ', str(time), '(' + str(timestamp) + ')')
            request_time = timestamp
            
            http = dpkt.http.Request(tcp.data)
            payload = urllib.parse.unquote(http.uri)
            print('-- request --\n {0} {1}\n'.format(http.method, payload))
            if(http.method == 'POST'):
                post_sent = True
        elif post_sent and tcp.sport == 80 and len(tcp.data) > 0:
            # Print out the timestamp in UTC
            time = datetime.datetime.utcfromtimestamp(timestamp)
            print('Timestamp: ', str(time), '(' + str(timestamp) + ')')
            response_time = timestamp

            http = dpkt.http.Response(tcp.data)
            print('-- response --\n{0}'.format(http.status))

            if(response_time - request_time >= 2.8):
                payload = payload[payload.find('LIMIT 1),') + 9:]
                idx = int(payload[:payload.find(',')]) - 1
                ch = chr(int(payload[payload.find('))=') + 3:payload.find(', SLEEP(3)')]))
                flag[idx] = ch
                print('\n\nFound!!\n\n flag[{0}] : {1}\n\ncurrent flag : {2}'.format(idx, ch, ''.join(flag)))
                sleep(0.1)
            post_sent = False
    return ''.join(flag)


def test():
    """Open up a test pcap file and print out the packets"""
    with open('dump.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print('flag : ' + analyze_packets(pcap))



if __name__ == '__main__':
    test()