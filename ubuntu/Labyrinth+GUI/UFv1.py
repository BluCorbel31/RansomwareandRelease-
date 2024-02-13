import os
import tkinter as tk
from tkinter import filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

class EncryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode

    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.encrypt_file(file_path)
        elif self.mode == "All":
            self.encrypt_all_files()

    def is_group(self, file_path):
        # Implement logic to check if file belongs to a group
        return False

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        with open(file_path + ".encrypted", "wb") as f:
            f.write(encrypted_data)
        os.remove(file_path)

    def encrypt_all_files(self):
        # Implement logic to encrypt all files in directory
        pass

class DecryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode

    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.decrypt_file(file_path)
        elif self.mode == "All":
            self.decrypt_all_files()

    def is_group(self, file_path):
        # Implement logic to check if file belongs to a group
        return False

    def decrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        decrypted_data = self.fernet.decrypt(data)
        with open(file_path[:-len(".encrypted")], "wb") as f:
            f.write(decrypted_data)
        os.remove(file_path)

    def decrypt_all_files(self):
        # Implement logic to decrypt all files in directory
        pass

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Labyrinth")

        self.label1 = tk.Label(master, text="Select a directory to monitor:")
        self.label1.pack()

        self.directory_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.directory_button.pack()

        self.label2 = tk.Label(master, text="Select a key file:")
        self.label2.pack()

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.pack()

        self.label3 = tk.Label(master, text="Select trigger for encryption:")
        self.label3.pack()

        self.encrypt_trigger = tk.StringVar()
        self.encrypt_trigger.set("Create")
        self.encrypt_trigger_menu = tk.OptionMenu(master, self.encrypt_trigger, "Create", "Delete", "Modify")
        self.encrypt_trigger_menu.pack()

        self.label4 = tk.Label(master, text="Select encryption mode:")
        self.label4.pack()

        self.encrypt_mode = tk.StringVar()
        self.encrypt_mode.set("Individual")
        self.encrypt_mode_menu = tk.OptionMenu(master, self.encrypt_mode, "Individual", "Group", "All")
        self.encrypt_mode_menu.pack()

        self.encrypt_label = tk.Label(master, text="Encryption Handler Status: Idle")
        self.encrypt_label.pack()

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
            self.handler = EncryptionHandler(self.load_key(), self.encrypt_trigger.get(), self.encrypt_mode.get())

            self.encrypt_observer = Observer()
            self.encrypt_observer.schedule(self.handler, self.directory, recursive=True)
            self.encrypt_observer.start()

            self.encrypt_label.config(text="Handler Status: Running")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Error", "Please select a directory and a key file.")

    def stop_monitoring(self):
        if hasattr(self, 'encrypt_observer'):
            self.encrypt_observer.stop()
            self.encrypt_observer.join()

            self.encrypt_label.config(text="Handler Status: Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def load_key(self):
        with open(self.key_file, "rb") as f:
            return f.read()

class DecryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Decryption")

        self.label1 = tk.Label(master, text="Select a directory to monitor:")
        self.label1.pack()

        self.directory_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.directory_button.pack()

        self.label2 = tk.Label(master, text="Select a key file:")
        self.label2.pack()

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.pack()

        self.label3 = tk.Label(master, text="Select trigger for decryption