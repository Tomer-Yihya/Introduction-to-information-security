import os
import sys
import base64

import addresses
from infosec.core import assemble
from search import GadgetSearch


PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_string(student_id):
    return 'Take me (%s) to your leader!' % student_id


def get_arg() -> bytes:
    """
    This function returns the (pre-encoded) `password` argument to be sent to
    the `sudo` program.

    This data should cause the program to execute our ROP-chain for printing our
    message in a finite loop of 16 iterations. Make sure to return a `bytes` object
    and not an `str` object.

    NOTES:
    1. Make sure your loop is executed exactly 16 times.
    2. Don't write addresses of gadgets directly - use the search object to
       find the address of the gadget dynamically.
    3. Make sure to call exit() at the end of your loop (any error code will do).

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the password argument.
    """
    search = GadgetSearch(LIBC_DUMP_PATH)
    # TODO: IMPLEMENT THIS FUNCTION
    raise NotImplementedError()
"""
    buffer_offset = 146*'d' # CHECK_PASSWORD_RETURN_ADDRESS - START_BUFF_ADDRESS + 4  (0xbfffe038 - 0xbfffdfaa + 4) = 146
    
    pop_eap = addresses.address_to_bytes(search.find('POP EAP'))            # POP EAP
                                                                            # "1" as a byte
    pop_ebx = addresses.address_to_bytes(search.find('POP EDX'))            # POP EDX
    auth_address = addresses.address_to_bytes(addresses.AUTH)               # Auth address
    pop_ebx = addresses.address_to_bytes(search.find('POP EDX'))            # MOV dword ptr [EDX], EAX
    
    
    
    
                                                                            # put address
    add_esp = addresses.address_to_bytes(search.find('ADD ESP, 4'))         # ADD ESP, 4
    string_address = addresses.address_to_bytes(addresses.STRING_ADDRESS)   # string address
    pop_edx = addresses.address_to_bytes(search.find('POP ESP'))            # POP ESP
                                                                            # put address
"""

def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)
