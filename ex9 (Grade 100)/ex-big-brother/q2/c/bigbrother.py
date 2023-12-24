import math
from scapy.all import *


LOVE = 'love'
unpersons = set()
high_entropy = 3.0

def spy(packet):
    """Check for love packets and encrypted packets.

    For each packet containing the word 'love', or a packed which is encrypted,
    add the sender's IP to the `unpersons` set.

    Notes:
    1. Use the global LOVE as declared above.
    """
    if TCP in packet:
        payload_bytes = bytes(packet[TCP].payload)
        payload_string = payload_bytes.decode('latin-1')
        if LOVE in payload_string or shannon_entropy(payload_string)>high_entropy:
            unpersons.add(packet[IP].src)
    

def shannon_entropy(string: str) -> float:
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    distribution = [float(string.count(c)) / len(string)
                    for c in set(string)]
    return -sum(p * math.log(p) / math.log(2.0) for p in distribution)


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(iface=get_if_list(), prn=spy)


if __name__ == '__main__':
    main()
