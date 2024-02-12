from cryptography.fernet import Fernet
import os

def generate_key():
    """
    Generates a new encryption key.
    """
    return Fernet.generate_key()

def save_key(key, key_file):
    """
    Saves the encryption key to a file.
    """
    with open(key_file, "wb") as f:
        f.write(key)

def load_key(key_file):
    """
    Loads the encryption key from a file.
    """
    with open(key_file, "rb") as f:
        return f.read()

def encrypt_file(key, file_path):
    """
    Encrypts a file using the given encryption key.
    """
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(file_path + ".encrypted", "wb") as f:
        f.write(encrypted_data)
    os.remove(file_path)

def main():
    # Define the directory containing files to encrypt
    directory = "/path/to/your/directory"

    # Define the file containing the encryption key
    key_file = "/path/to/your/keyfile.key"

    # Generate or load the encryption key
    if not os.path.exists(key_file):
        key = generate_key()
        save_key(key, key_file)
    else:
        key = load_key(key_file)

    # Encrypt all files in the directory
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            encrypt_file(key, file_path)

if __name__ == "__main__":
    main()