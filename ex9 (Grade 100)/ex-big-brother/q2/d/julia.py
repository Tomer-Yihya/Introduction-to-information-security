import socket
import sys
from scapy.all import *



SRC_PORT = 65000
TIME_OUT = 7
MASK = 7

def receive_message(port: int) -> str:
    """Receive *hidden* messages on the given TCP port.

    As Winston sends messages encoded over the TCP metadata, re-implement this
    function so to be able to receive the messages correctly.

    Notes:
    1. Use `SRC_PORT` as part of your implementation.
    """
    triplets = -1
    packets_from_winston = [-1]    
    
    while True:
        # if we got all triplets - break
        if(-1 not in packets_from_winston):
            break 

        packets = sniff(iface=get_if_list(), timeout=TIME_OUT)
                    
        if len(packets) > 0: #If we didn't get any packets we defently didn't recieve Winston msg'
            for packet in packets:
                if TCP in packet and packet[TCP].sport==SRC_PORT and packet[TCP].dport==port:
                    # first packet
                    if triplets==-1: 
                        triplets = packet[TCP].ack
                        packets_from_winston = [-1 for i in range(triplets)] #Data structure to keep track of triplets we got
                    packets_from_winston[packet[TCP].seq-1] = packet[TCP].reserved
            
         
    # assemble the triplets to a msg
    msg = 0
    for reserved_bits in packets_from_winston:
        msg = msg << 3
        msg += reserved_bits&MASK           
    
    # convert it to bytes
    msg_bytes = msg.to_bytes((msg.bit_length()+5)//8,sys.byteorder)
    msg_string = msg_bytes.decode('latin-1')
    return msg_string




def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
