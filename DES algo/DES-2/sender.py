import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import binascii

def encrypt_message(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), DES.block_size))
    return ciphertext

def main():
    host = '127.0.0.1'
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    print(f"Sender Connected to {host}")

    message = input("Enter message to be encrypted:\n")
    print("\nENCRYPTION")
    print(f"Original Message: {message}")

    key = b'sixteenB'
    cipher = DES.new(key, DES.MODE_ECB)

    # Display each round of encryption
    for round_num in range(1, 17):
        # Encrypt the message for this round
        partial_ciphertext = cipher.encrypt(pad(message.encode('utf-8'), DES.block_size))
        print(f"Round {round_num} Encrypted Message: {binascii.hexlify(partial_ciphertext).decode('utf-8')}")

    ciphertext = encrypt_message(message, key)

    print(f"\nEncrypted Message: {binascii.hexlify(ciphertext).decode('utf-8')}")

    client_socket.sendall(ciphertext)

    client_socket.close()

if __name__ == "__main__":
    main()
