import os
import tkinter as tk
from tkinter import filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

# Snowflake integration (simplified)
def upload_to_snowflake(file_path):
    # Placeholder function to upload file to Snowflake
    print("Uploading", file_path, "to Snowflake")

def download_from_snowflake(file_path):
    # Placeholder function to download file from Snowflake
    print("Downloading", file_path, "from Snowflake")

# EncryptionHandler class definition
class EncryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode

    # Event handler for file creation
    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Event handler for file deletion
    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Event handler for file modification
    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Handle encryption for individual or group files
    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.encrypt_file(file_path)
        elif self.mode == "All":
            self.encrypt_all_files()

    # Placeholder method for determining group membership
    def is_group(self, file_path):
        return False

    # Encrypt a single file
    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        with open(file_path + ".encrypted", "wb") as f:
            f.write(encrypted_data)
        os.remove(file_path)
        # Upload encrypted file to Snowflake
        upload_to_snowflake(file_path + ".encrypted")

    # Placeholder method for encrypting all files in a directory
    def encrypt_all_files(self):
        pass

# Main function to run the GUI
def main():
    root = tk.Tk()
    root.title("Labyrinth")

    # Create EncryptionApp instance
    encryption_app = EncryptionApp(root)

    # Add headers and footers
    header_label = tk.Label(root, text="Labyrinth - File Encryption Tool", font=("Helvetica", 16, "bold"))
    header_label.pack()

    footer_label = tk.Label(root, text="Created by Blu Corbel", font=("Helvetica", 10))
    footer_label.pack(side="bottom")

    root.mainloop()

# Run the main function
if __name__ == "__main__":
    main()