import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

class EncryptionHandler(FileSystemEventHandler):
    def __init__(self, key):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.encrypt_file(file_path)

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        with open(file_path + ".encrypted", "wb") as f:
            f.write(encrypted_data)
        os.remove(file_path)

class DecryptionHandler(FileSystemEventHandler):
    def __init__(self, key):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.decrypt_file(file_path)

    def decrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = self.fernet.decrypt(encrypted_data)
        original_file = file_path[:-len(".encrypted")]
        with open(original_file, "wb") as f:
            f.write(decrypted_data)
        os.remove(file_path)

def load_key(key_file):
    """
    Loads the encryption key from a file.
    """
    with open(key_file, "rb") as f:
        return f.read()

def main():
    # Define the directory to monitor
    directory = "/path/to/your/directory"

    # Define the file containing the encryption key
    key_file = "/path/to/your/keyfile.key"

    # Load the encryption key
    with open(key_file, "rb") as f:
        key = f.read()

    # Start monitoring the directory for file creations
    encryption_handler = EncryptionHandler(key)
    decryption_handler = DecryptionHandler(key)

    observer = Observer()
    observer.schedule(encryption_handler, directory, recursive=True)
    observer.schedule(decryption_handler, directory, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()