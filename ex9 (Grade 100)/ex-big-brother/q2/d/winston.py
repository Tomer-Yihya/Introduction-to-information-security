import socket
import sys
from scapy.all import *



SRC_PORT = 65000


def send_message(ip: str, port: int):
    """Send a *hidden* message to the given ip + port.

    Julia expects the message to be hidden in the TCP metadata, so re-implement
    this function accordingly.

    Notes:
    1. Use `SRC_PORT` as part of your implementation.
    """
    
    msg = b'I love you' + b'\0\0'
    msg = bytearray(msg)
            
    #Transform msg to int so we can manipulate it
    msg_int = int.from_bytes(msg, sys.byteorder)
    
    #Send the triplets
    triplets = int(len(msg)*8/3) 
    for i in range(triplets):
        triplet = msg_int & 7  # get the 3 LSB bits
        msg_int = msg_int >> 3 # Shift so we can get the next 3 LSB bits
        
        l1 = IP(dst=ip)
        l2 = TCP(sport=SRC_PORT, dport=port, flags='SA', seq=triplets-i, ack=triplets, reserved=triplet)
        s = l1/l2
        send(s)


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
