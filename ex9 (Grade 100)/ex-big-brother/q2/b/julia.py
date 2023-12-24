import socket
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding

#Initialize cipher and padder
key = b'cos ememememk!!!'
iv = b'1234123412341234'

def receive_message(port: int) -> str:
    """Receive *encrypted* messages on the given TCP port.

    As Winston sends encrypted messages, re-implement this function so to
    be able to decrypt the messages.

    Notes:
    1. The encryption is based on AES.
    2. Julia and Winston already have a common shared key, just define it on your own.
    3. Mind the padding! AES works in blocks of 16 bytes.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    remove_pad = padding.PKCS7(128).unpadder()

    listener = socket.socket()
    try:
        listener.bind(('', port))
        listener.listen(1)
        connection, address = listener.accept()
        try:
            pad_text = cipher.decrypt(connection.recv(1024)) 
            unpad_text = remove_pad.update(pad_text)
            unpad_text += remove_pad.finalize()
            return unpad_text.decode("latin-1")
        finally:
            connection.close()
    finally:
        listener.close()


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
