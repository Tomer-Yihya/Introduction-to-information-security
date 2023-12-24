import os
import sys

def check_message(path: str) -> bool:
    """
    Return True if `msgcheck` would return 0 for the file at the specified path,
    return False otherwise.
    :param path: The file path.
    :return: True or False.
    """
    #seems like import os not work, i missed import sys lol
    if os.path.getsize(path) <=1:#the file have at most 1 byte we need at least 2
        return False
    
    with open(path, 'rb') as reader:
        # Read data from the file, do whatever magic you need
        #raise NotImplementedError()
        
        leni = reader.read(1) #first byte
        
        leni = int.from_bytes(leni, byteorder = sys.byteorder) #should be the number of bytes from 
            #the third byte which we want to XOR
            
        desired = reader.read(1) #the second byte is the desired result of the XOR's'
        
        result = bytes.fromhex('72') #the constant in the beginning of the 'validate' function
        
        for i in range(leni):
            cur_byte = reader.read(1)
            
            if not cur_byte:#end of the file, file size smaller than leni
                break
            
            #from https://nitratine.net/blog/post/xor-python-byte-strings/
            #xor byte by byte, like in the previous exercise
            result = bytes( [_a ^ _b for _a, _b in zip(result, cur_byte)])

        return True if result == desired else False #true if the XOR of the bytes is the desired result
        
        
def main(argv):
    if len(argv) != 2:
        print('USAGE: python {} <msg-file>'.format(argv[0]))
        return -1
    path = argv[1]
    if check_message(path):
        print('valid message')
        return 0
    else:
        print('invalid message')
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
