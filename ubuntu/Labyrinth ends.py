from cryptography.fernet import Fernet
import os

def load_key(key_file):
    """
    Loads the encryption key from a file.
    """
    with open(key_file, "rb") as f:
        return f.read()

def decrypt_file(key, encrypted_file):
    """
    Decrypts an encrypted file using the given encryption key.
    """
    fernet = Fernet(key)
    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    original_file = encrypted_file[:-len(".encrypted")]
    with open(original_file, "wb") as f:
        f.write(decrypted_data)
    os.remove(encrypted_file)

def main():
    # Define the directory containing encrypted files
    directory = "/path/to/your/directory"

    # Define the file containing the encryption key
    key_file = "/path/to/your/keyfile.key"

    # Load the encryption key
    key = load_key(key_file)

    # Decrypt all encrypted files in the directory
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) and filename.endswith(".encrypted"):
            decrypt_file(key, file_path)

if __name__ == "__main__":
    main()