pip install watchdog

import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

class MyHandler(FileSystemEventHandler):
    def __init__(self, key):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            self.encrypt_file(file_path)

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        with open(file_path + ".encrypted", "wb") as f:
            f.write(encrypted_data)
        os.remove(file_path)

def main():
    # Define the directory to monitor
    directory = "/path/to/your/directory"

    # Define the file containing the encryption key
    key_file = "/path/to/your/keyfile.key"

    # Load the encryption key
    with open(key_file, "rb") as f:
        key = f.read()

    # Start monitoring the directory for file creations
    event_handler = MyHandler(key)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()

#decryption automated.

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