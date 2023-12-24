import socket
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding


key = b'cos ememememk!!!'
iv = b'1234123412341234'
message = b'I love you'

def send_message(ip: str, port: int):
    """Send an *encrypted* message to the given ip + port.

    Julia expects the message to be encrypted, so re-implement this function accordingly.

    Notes:
    1. The encryption is based on AES.
    2. Julia and Winston already have a common shared key, just define it on your own.
    3. Mind the padding! AES works in blocks of 16 bytes.
    """
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    add_pad = padding.PKCS7(128).padder()

    #Create the padded msg
    pad_data = add_pad.update(message)
    pad_data += add_pad.finalize()
    
    #Create the encoded msg
    cipher_text = cipher.encrypt(pad_data)

    connection = socket.socket()
    try:
        connection.connect((ip, port))
        connection.send(cipher_text)
    finally:
        connection.close()


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
