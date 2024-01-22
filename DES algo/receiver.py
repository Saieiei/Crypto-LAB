import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import binascii

def receive_message(conn):
    data = conn.recv(1024)
    return data

def decrypt_message(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_text.decode('utf-8')

def main():
    host = '127.0.0.1'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print("Receiver waiting for connection...")
    conn, addr = server_socket.accept()
    print(f"Receiver connected to {addr}")

    ciphertext = receive_message(conn)
    print(f"Received Encrypted Message: {binascii.hexlify(ciphertext).decode('utf-8')}")

    key = b'sixteenB'
    decrypted_message = decrypt_message(ciphertext, key)

    print("\nDECRYPTION")
    print(f"Encrypted Message: {binascii.hexlify(ciphertext).decode('utf-8')}")
    print(f"Decrypted Message: {decrypted_message}")

    conn.close()

if __name__ == "__main__":
    main()
