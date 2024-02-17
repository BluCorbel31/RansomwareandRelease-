import os
import tkinter as tk
from tkinter import filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import snowflake.connector

# Snowflake connection parameters (replace with your actual Snowflake credentials)
snowflake_user = 'your_username'
snowflake_password = 'your_password'
snowflake_account = 'your_account'
snowflake_database = 'your_database'
snowflake_schema = 'your_schema'
snowflake_warehouse = 'your_warehouse'

# Function to establish Snowflake connection
def get_snowflake_connection():
    return snowflake.connector.connect(
        user=snowflake_user,
        password=snowflake_password,
        account=snowflake_account,
        warehouse=snowflake_warehouse,
        database=snowflake_database,
        schema=snowflake_schema
    )

# Function to upload file to Snowflake stage
def upload_to_snowflake_stage(file_path):
    try:
        connection = get_snowflake_connection()
        cursor = connection.cursor()
        cursor.execute(f'PUT file://{file_path} @%YOUR_STAGE_DIRECTORY/')
        cursor.close()
        connection.close()
        print(f"File {file_path} uploaded to Snowflake stage successfully")
    except Exception as e:
        print(f"Error uploading file to Snowflake stage: {e}")

# Function to copy file from Snowflake stage to table
def copy_to_snowflake_table(file_path):
    try:
        connection = get_snowflake_connection()
        cursor = connection.cursor()
        cursor.execute(f"COPY INTO YOUR_TABLE FROM @%YOUR_STAGE_DIRECTORY/{os.path.basename(file_path)} FILE_FORMAT=(TYPE='CSV')")
        cursor.close()
        connection.close()
        print(f"File {file_path} copied to Snowflake table successfully")
    except Exception as e:
        print(f"Error copying file to Snowflake table: {e}")

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
        # Upload encrypted file to Snowflake stage
        upload_to_snowflake_stage(file_path + ".encrypted")

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