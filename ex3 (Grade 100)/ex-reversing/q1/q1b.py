import sys
"""
    The idea of fixing in this function is: we XOR the data[0] bytes from the third byte
    then check if it equal to the second byte i.e. data[1]. so the idea is to check
    what is the result of the XOR and that result write as the second byye, that
    way we only change one byte at the file and still making the msgcheck code return 0
"""
def fix_message_data(data: bytes) -> bytes:
    """
    Implement this function to return the "fixed" message content. This message
    should have minimal differences from the original message, but should pass
    the check of `msgcheck`.

    :param data: The source message data.
    :return: The fixed message data.
    """
    #raise NotImplementedError()
    leni = bytes([data[0]]) #first byte
    leni = int.from_bytes(leni, byteorder = sys.byteorder) #should be the number of bytes from 
        #the third byte which we want to XOR
    
    result = bytes.fromhex('72') #the constant in the beginning of the 'validate' function
    
    leni = leni if leni+2<len(data) else len(data)-2 #we read from list and we don't want to 
        #get out of bound the list, leni might be bigger the len(data)
    
    for i in range(2, leni+2):#we want to start from the third byte
        cur_byte = bytes([data[i]])
        
        #from https://nitratine.net/blog/post/xor-python-byte-strings/
        #xor byte by byte, like in the previous exercise
        result = bytes( [_a ^ _b for _a, _b in zip(result, cur_byte)])
    
    #print(type(data))
    modi_data = bytes([data[0]]) + result + bytes(data[2:])
    
    return modi_data
    
    #try somthing
    #modified_data = bytearray(data)  #change the second byte to the result of the XOR
    #print(type(result))
    #print(type(0xFF))
    #modified_data[1] = int.from_bytes(result, byteorder = sys.byteorder)
    #print(b'int.from_bytes(result, byteorder = sys.byteorder)' == result)
    #return bytes(modified_data)  
    

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
