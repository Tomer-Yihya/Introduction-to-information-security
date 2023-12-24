def patch_program_data(program: bytes) -> bytes:
    """
    Implement this function to return the patched program. This program should
    return 0 for all input files.

    The fix in this file should be *different* than the fix in q1d.py.

    :param data: The bytes of the source program.
    :return: The bytes of the patched program.
    """
    #raise NotImplementedError()
    
    arr_prog = bytearray(program)# so we will be able to modify the bytes
    
    arr_prog[1757: 1762] = b'\xb8\x00\x00\x00\x00' #in this bytes (by ida)
    #is the 'mov eax, 1' instruction in the invalid code block, what this line
    #does it "put" b'\xb8\x00\x00\x00\x00' instead of 'mov eax, 1',
    #this is the opcode for 'mov eax, 0' instruction, so now the program
    #will always return 0 after the valid function, regardless the validation of the message
    
    return bytes(arr_prog)


def patch_program(path):
    with open(path, 'rb') as reader:
        data = reader.read()
    patched = patch_program_data(data)
    with open(path + '.patched', 'wb') as writer:
        writer.write(patched)


def main(argv):
    if len(argv) != 2:
        print('USAGE: python {} <msgcheck-program>'.format(argv[0]))
        return -1
    path = argv[1]
    patch_program(path)
    print('done')


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
