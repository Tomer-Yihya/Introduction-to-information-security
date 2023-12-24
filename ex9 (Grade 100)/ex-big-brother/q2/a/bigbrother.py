from scapy.all import *


LOVE = 'love'
unpersons = set()


def spy(packet):
    """Check for love packets.

    For each packet containing the word 'love', add the sender's IP to the
    `unpersons` set.

    Notes:
    1. Use the global LOVE as declared above.
    """
    if TCP in packet:
        payload_bytes = bytes(packet[TCP].payload)
        payload_string = payload_bytes.decode('latin-1')
        if LOVE in payload_string:
            unpersons.add(packet[IP].src)
    

def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(iface=get_if_list(), prn=spy)


if __name__ == '__main__':
    main()
