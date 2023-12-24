import time
import os
from scapy.all import *


WINDOW = 60
MAX_ATTEMPTS = 15


# Initialize your data structures here
# Initialize your data structures
ip_times = {}

blocked = set()  # We keep blocked IPs in this set


def on_packet(packet):
    """This function will be called for each packet.

    Use this function to analyze how many packets were sent from the sender
    during the last window, and if needed, call the 'block(ip)' function to
    block the sender.

    Notes:
    1. You must call block(ip) to do the blocking.
    2. The number of SYN packets is checked in a sliding window.
    3. Your implementation should be able to efficiently handle multiple IPs.
    """
    curr_time = time.time()
    if TCP in packet and packet[TCP].flags=='S':
        ip = packet[IP].src
        port = packet[TCP].sport

        if is_blocked(ip)==False:             # if this ip already blocked - ignore it
            if ip not in ip_times.keys():     # if first time we got a packet from this IP
                ip_times[ip] = []
            ip_times[ip].append(curr_time)
            
            # update ip list save only relevant ip times
            new_list = []
            for i in ip_times[ip]:
                if i>=(curr_time-WINDOW):
                    new_list.append(i)

            ip_times[ip] = new_list
            
            #Check if we add 15 SYN packets 
            if len(ip_times[ip]) >= MAX_ATTEMPTS:
                block(ip)


def generate_block_command(ip: str) -> str:
    """Generate a command that when executed in the shell, blocks this IP.

    The blocking will be based on `iptables` and must drop all incoming traffic
    from the specified IP."""
    return "sudo iptables -A INPUT -s "+str(ip)+" -j DROP"


def block(ip):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    os.system(generate_block_command(ip))
    blocked.add(ip)


def is_blocked(ip):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    return ip in blocked


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
