from cryptography.fernet import Fernet

def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

if __name__ == "__main__":
    key = input("Enter the encryption key: ")
    encrypted_message = input("Enter the encrypted message: ").encode()
    decrypted_message = decrypt_message(encrypted_message, key)
    print("Decrypted message:", decrypted_message)