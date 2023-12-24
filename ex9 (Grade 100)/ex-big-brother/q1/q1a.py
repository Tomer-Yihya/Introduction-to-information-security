from scapy.all import *
from typing import List, Iterable


OPEN = 'open'
CLOSED = 'closed'
FILTERED = 'filtered'


def generate_syn_packets(ip: str, ports: List[int]) -> list:
    """
    Returns a list of TCP SYN packets, to perform a SYN scan on the given
    TCP ports.

    Notes:
    1. Do NOT add any calls of your own to send/receive packets.
    """
    syn_packets = []
    for port in ports:
        ip_packet = IP(dst=ip)                   # create paket with desired ip
        tcp_packet = TCP(dport=port, flags='S')  # create TCP with desired port with SYN flag
        s = ip_packet / tcp_packet               # create paket
        syn_packets.append(s)
    
    return syn_packets


def analyze_scan(ip: str, ports: List[int], answered: Iterable, unanswered: Iterable) -> dict:
    """Analyze the results from `sr` of SYN packets.

    This function returns a dictionary from port number (int), to
    'open' / 'closed' / 'filtered' (strings), based on the answered and unanswered
    packets returned from `sr`.

    Notes:
    1. Use the globals OPEN / CLOSED / FILTERED as declared above.
    """
    results = dict()
    
    # answered ports
    for packet in answered:
        flags = packet[1][TCP].flags
        if flags!='SA': # close
            results[packet[1][TCP].sport] = CLOSED
        else:  # open (flags == 'SA')
            results[packet[1][TCP].sport] = OPEN
    
    # unanswered ports - filtered
    for packet in unanswered:
        results[packet[TCP].dport] = FILTERED
             
    return results


def stealth_syn_scan(ip: str, ports: List[int], timeout: int):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    packets = generate_syn_packets(ip, ports)
    answered, unanswered = sr(packets, timeout=timeout)
    return analyze_scan(ip, ports, answered, unanswered)


def main(argv):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    if not 3 <= len(argv) <= 4:
        print('USAGE: %s <ip> <ports> [timeout]' % argv[0])
        return 1
    ip = argv[1]
    ports = [int(port) for port in argv[2].split(',')]
    if len(argv) == 4:
        timeout = int(argv[3])
    else:
        timeout = 5
    results = stealth_syn_scan(ip, ports, timeout)
    for port, result in results.items():
        print('port %d is %s' % (port, result))


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
