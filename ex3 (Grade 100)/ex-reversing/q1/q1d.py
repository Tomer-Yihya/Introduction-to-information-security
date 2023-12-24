def patch_program_data(program: bytes) -> bytes:
    """
    Implement this function to return the patched program. This program should
    return 0 for all input files.

    :param data: The bytes of the source program.
    :return: The bytes of the patched program.
    """
    #raise NotImplementedError()
    arr_prog = bytearray(program)# so we will be able to modify the bytes
    
    arr_prog[1739] = 0xEB #in this byte (by ida) is the 'jnz' instruction after
    #the validate function, what this line does it "put" 0xEB instead of jnz,
    #0xEB is the opcode for 'j' instruction, so no matter the cmp result we always
    #follow the valid code branch 
    
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
