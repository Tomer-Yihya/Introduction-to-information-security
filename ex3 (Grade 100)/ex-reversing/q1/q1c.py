"""
    The idea of fixing in this function is: we XOR the data[0] bytes from the third byte
    then check if it equal to the second byte i.e. data[1]. so the idea is to change data[0]
    to value one so it will only xor the third byte with the const in the program which is 0x72, the
    main idea is that we add a byte after the second byte which is the xor result of the second byte
    and the const, that way the msgcheck code xor only one block, and the block it xor is the
    block we wanted, meaning after the xor we will get back the second byte (as a xor( a xor b ) == b)
    and of course it's equal to the second byte so the code of msgcheck will return 0
"""
def fix_message_data(data: bytes) -> bytes:
    """
    Implement this function to return the "fixed" message content. This message
    should have minimal differences from the original message, but should pass
    the check of `msgcheck`.

    The fix in this file should be *different* than the fix in q1b.py.

    :param data: The source message data.
    :return: The fixed message data.
    """
    #raise NotImplementedError()
        
    const = bytes.fromhex('72') #the constant in the beginning of the 'validate' function
    
    
    #the result of the xor between the const and the second byte
    correct_xor = bytes( [_a ^ _b for _a, _b in zip(const, bytes([data[1]]))])
    
    #pita = bytes( [_a ^ _b for _a, _b in zip(const, correct_xor)])
    #print(pita == bytes([data[1]]))
    
    #make that the code xor only the third byte and the const which will give back
    #the second byte
    return bytes([1]) + bytes([data[1]]) + correct_xor + bytes(data[2:])
    


def fix_message(path):
    with open(path, 'rb') as reader:
        data = reader.read()
    fixed_data = fix_message_data(data)
    with open(path + '.fixed', 'wb') as writer:
        writer.write(fixed_data)


def main(argv):
    if len(argv) != 2:
        print('USAGE: python {} <msg-file>'.format(argv[0]))
        return -1
    path = argv[1]
    fix_message(path)
    print('done')


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
