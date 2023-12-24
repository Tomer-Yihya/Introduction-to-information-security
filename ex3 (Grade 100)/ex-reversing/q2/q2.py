from infosec.core import assemble


def patch_program_data(program: bytes) -> bytes:
    """
    Implement this function to return the patched program. This program should
    execute lines starting with #!, and print all other lines as-is.

    Use the `assemble` module to translate assembly to bytes. For help, in the
    command line run:

        ipython3 -c 'from infosec.core import assemble; help(assemble)'

    :param data: The bytes of the source program.
    :return: The bytes of the patched program.
    """
    #raise NotImplementedError()
   
    #get the binary of our two assembles
    big_patch = bytearray(assemble.assemble_file("patch2.asm"))
    small_patch = bytearray(assemble.assemble_file("patch1.asm"))
    
    prog = bytearray(program)
    
    #print(len(big_patch))
    #print(len(small_patch))
    
    #inject our big patch to the binary from offset 1485, when the big block nop's starts
    for i in range (0, len(big_patch)):
        prog[1485+i] = big_patch[i]
    
    #inject our small patch to the binary from offset 1587, when the small block of nop's starts
    for i in range(0, len(small_patch)):
        prog[1587+i] = small_patch[i]
    
    return bytes(prog)
    """
    not work try something else
    start_prog = program[:1485]
    print(len(start_prog))
    prog = bytearray(program)
    big_patch = bytearray(assemble.assemble_file("patch2.asm"))
    small_patch = bytearray(assemble.assemble_file("patch1.asm"))
    print(prog[1483 : 1537])
    print(prog[1584 : 1598])
    prog[1485 : 1530] = big_patch
    prog[1587 : 1592] = small_patch
    print(prog[1483 : 1537])
    print("ok")
    print(big_patch)
    print("ok")
    print(prog[1584 : 1598])
    print("ok")
    print(small_patch)
    """
    
    


def patch_program(path):
    with open(path, 'rb') as reader:
        data = reader.read()
    patched = patch_program_data(data)
    with open(path + '.patched', 'wb') as writer:
        writer.write(patched)


def main(argv):
    if len(argv) != 2:
        print('USAGE: python {} <readfile-program>'.format(argv[0]))
        return -1
    path = argv[1]
    patch_program(path)
    print('done')


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
