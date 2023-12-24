class RepeatedKeyCipher:

    def __init__(self, key: bytes = bytes([0, 0, 0, 0, 0])):
        """Initializes the object with a list of integers between 0 and 255."""
        # WARNING: DON'T EDIT THIS FUNCTION!
        self.key = list(key)

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypts a given plaintext string and returns the ciphertext."""
        # TODO: Test THIS FUNCTION
        #this block make the key bigger or same size as the plaintext
        keyi = self.key
        #key may be size 0 (happen to me) so to not make division in 0 check before
        leni = len(plaintext) if len(keyi) == 0 else int(len(plaintext)/len(keyi))+1
        keyi = keyi*leni #make keyi at least as long as plaintext

        str_bytes = plaintext.encode('latin-1')
        
        #from https://nitratine.net/blog/post/xor-python-byte-strings/
        #xor byte by byte
        result = bytes( [_a ^ _b for _a, _b in zip(keyi, str_bytes)])

        return result
    
        #raise NotImplementedError()

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypts a given ciphertext string and returns the plaintext."""
        # TODO: IMPLEMENT THIS FUNCTION
        #this block make the key bigger or same size as the plaintext
        keyi = self.key
        #key may be size 0 (happen to me) so to not make division in 0 check before
        leni = len(ciphertext) if len(keyi) == 0 else int(len(ciphertext)/len(keyi))+1
        keyi = keyi*leni #make keyi at least as long as plaintext
        
        #from https://nitratine.net/blog/post/xor-python-byte-strings/
        #xor byte by byte
        str_bytes = bytes( [_a ^ _b for _a, _b in zip(keyi, ciphertext)])
        
        #now decode the bytes back to string
        result = str_bytes.decode('latin-1')

        return result

        #raise NotImplementedError()


class BreakerAssistant:

    def plaintext_score(self, plaintext: str) -> float:
        """Scores a candidate plaintext string, higher means more likely."""
        # Please don't return complex numbers, that would be just annoying.
        # TODO: IMPLEMENT THIS FUNCTION
        
        #edge case, empty plaintext
        if(len(plaintext) == 0):
            return 0
        
        result = 0
        #we count the english letters and the spaces in the plaintext,
        #also add count with smaller value to numbers and some characters
        for sign in plaintext:
            if sign == ' ' or 'A' <= sign <= 'Z' or 'a'<= sign <= 'z':
                result +=1
            elif sign == '!' or sign == '?' or sign == '.' or sign == ',':
                result +=  0.5
            elif '0' <= sign <= '9':
                result += 0.1
            
            

        return result/len(plaintext)#the precentage of "Englishness" of the plaintext

        #raise NotImplementedError()

    

    def brute_force(self, cipher_text: bytes, key_length: int) -> str:
        """Breaks a Repeated Key Cipher by brute-forcing all keys."""
        # TODO: IMPLEMENT THIS FUNCTION
        
        #initialization
        max_score = -1
        str_max = "" #the string represent the maximum score
        lim = 2**(8*key_length) #the limit
        
        #we search for all the possiable keys (2^(8*key_length)) which one bring the most "logical" result
        for i in range(0, lim):
            key = []#init, need this?
            
            #generate the i'th key, by using & 255 on each byte
            num = i
            while num > 0:#until we pass all bytes
                key.append(num & 255) #the next byte of the key
                num >>=8 #move to the next byte
            
            #make RepeatedKeyCipher object
            tmp = bytes(key)
            key = RepeatedKeyCipher(tmp)
            
            #decrypt the cipher text using the key we create
            posib_str = key.decrypt(cipher_text)
            
            #calcute the score of the decryption
            curr_score = self.plaintext_score(posib_str)
            
            
            if(curr_score > max_score):
                max_score = curr_score #save the current score as the maximum
                str_max = posib_str #save the decrypted plaintext fit the score
                    
        #print(max_score) #debug
        return str_max
        #raise NotImplementedError()
    
    """
        This function use brute force method but on single byte, meaning we have only 256 possiable value
        to the fitting key
        
        lst_cipher - list of the bytes of the cipher that are XOR with the i'th byte in the key
        @ret - return the key value that maximize the score on the given lst_cipher
    """
    def break_byte(self, lst_cipher):
        
        #initialization
        max_score = -1
        key_max = 0
        cipher_byte = bytes(lst_cipher)
        
        #brute force each possiable key which his size is byte
        for i in range(0, 256):

            #make RepeatedKeyCipher object
            tmp = bytes([i])
            key = RepeatedKeyCipher(tmp)
            
            #decrypt the plaintext using the key we create and calcute the score of the decryption
            posib_str = key.decrypt(cipher_byte)
            curr_score = self.plaintext_score(posib_str)

            if(curr_score > max_score):
                max_score = curr_score #save the current score as the maximum
                key_max = i #save the key that gave the current score
            
        #print(max_score)
        return key_max

    def smarter_break(self, cipher_text: bytes, key_length: int) -> str:
        """Breaks a Repeated Key Cipher any way you like."""
        # TODO: IMPLEMENT THIS FUNCTION
        #initialization
        key = []
        break_key = [list() for i in range(0, key_length)] #make list of lists in size of key_length
        
        
        #the i'th byte in the cipher in encrypted by the i'th % key_length byte in the key
        #so all we need to do is gathering the bytes from the cipher that fit to the i'th byte
        #in the key and insert them in break_key[i]
        for i in range(0, len(cipher_text)):
            break_key[i % key_length].append(cipher_text[i])
        
        #now we find each possiable byte of the key using break_byte function
        for item in break_key:
            key.append(self.break_byte(item))
        
        #make RepeatedKeyCipher object
        keyi = RepeatedKeyCipher(bytes(key))

        return keyi.decrypt(cipher_text) #return the possiable decrypted plain text
        
        #raise NotImplementedError()
