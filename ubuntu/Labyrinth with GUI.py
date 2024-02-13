import os
import tkinter as tk
from tkinter import filedialog, messagebox
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

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("File Encryption Tool")

        self.label = tk.Label(master, text="Select a directory to monitor:")
        self.label.pack()

        self.directory_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.directory_button.pack()

        self.key_label = tk.Label(master, text="Select a key file:")
        self.key_label.pack()

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.pack()

        self.encrypt_label = tk.Label(master, text="Encryption Handler Status: Idle")
        self.encrypt_label.pack()

        self.decrypt_label = tk.Label(master, text="Decryption Handler Status: Idle")
        self.decrypt_label.pack()

        self.start_button = tk.Button(master, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack()

        self.stop_button = tk.Button(master, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack()

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.directory_button.config(text="Selected Directory: " + self.directory)

    def select_key(self):
        self.key_file = filedialog.askopenfilename()
        self.key_button.config(text="Selected Key File: " + self.key_file)

    def start_monitoring(self):
        if hasattr(self, 'directory') and hasattr(self, 'key_file'):
            self.encrypt_handler = EncryptionHandler(self.load_key())
            self.decrypt_handler = DecryptionHandler(self.load_key())

            self.encrypt_observer = Observer()
            self.encrypt_observer.schedule(self.encrypt_handler, self.directory, recursive=True)
            self.encrypt_observer.start()

            self.decrypt_observer = Observer()
            self.decrypt_observer.schedule(self.decrypt_handler, self.directory, recursive=True)
            self.decrypt_observer.start()

            self.encrypt_label.config(text="Encryption Handler Status: Running")
            self.decrypt_label.config(text="Decryption Handler Status: Running")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Error", "Please select a directory and a key file.")

    def stop_monitoring(self):
        if hasattr(self, 'encrypt_observer') and hasattr(self, 'decrypt_observer'):
            self.encrypt_observer.stop()
            self.decrypt_observer.stop()

            self.encrypt_observer.join()
            self.decrypt_observer.join()

            self.encrypt_label.config(text="Encryption Handler Status: Stopped")
            self.decrypt_label.config(text="Decryption Handler Status: Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def load_key(self):
        with open(self.key_file, "rb") as f:
            return f.read()

root = tk.Tk()
app = EncryptionApp(root)
root.mainloop()