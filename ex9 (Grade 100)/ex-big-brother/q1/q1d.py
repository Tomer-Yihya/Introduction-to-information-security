from scapy.all import *


def on_packet(packet):
    """Implement this to send a SYN ACK packet for every SYN.

    Notes:
    1. Use *ONLY* the `send` function from scapy to send the packet!
    """
    if TCP in packet:
        if packet[TCP].flags=='S':
            # IP layer
            src_ip = packet[IP].src
            l1 = IP(dst=src_ip)
            
            # TCP layer
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            seq_number = packet[TCP].seq
            ack_number = packet[TCP].ack
            l2 = TCP(sport=destination_port, 
                     dport=source_port, 
                     flags='SA', 
                     seq=ack_number, 
                     ack=seq_number + 1)
            
            return_packet = l1/l2 
            send(return_packet)


def main(argv):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(prn=on_packet)


if __name__ == '__main__':
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    import sys
    sys.exit(main(sys.argv))
