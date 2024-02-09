from cryptography.fernet import Fernet

def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

if __name__ == "__main__":
    key = Fernet.generate_key()
    message = "Hello, world!"
    encrypted_message = encrypt_message(message, key)
    print("Encrypted message:", encrypted_message.decode())