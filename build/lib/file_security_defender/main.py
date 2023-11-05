import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
import os
import logging
import re
import sys

class FileSecurityDefender:
    def __init__(self, root):
        self.root = root
        self.root.title("File Security Defender")
        self.password = None
        self.selected_file = None
        self.key = None
        self.backup_dir = "key_backup"
        self.private_key = None

        self.setup_logging()
        self.logger = logging.getLogger(__name__)

        self.setup_ui()
        self.load_or_generate_key_pair()

    def setup_logging(self):
        log_filename = "app.log"
        logging.basicConfig(filename=log_filename, level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    def setup_ui(self):
        self.upload_button = tk.Button(self.root, text="Upload File", command=self.upload_file)
        self.upload_button.pack()

        self.download_button = tk.Button(self.root, text="Download Decrypted File", state=tk.DISABLED, command=self.download_decrypted_file)
        self.download_button.pack()

        self.logout_button = tk.Button(self.root, text="Log out", command=self.logout)
        self.logout_button.pack()

        self.filename_label = tk.Label(self.root, text="")
        self.filename_label.pack()

    def load_or_generate_key_pair(self):
        try:
            self.password = self.get_secure_password()
            if self.password:
                if os.path.exists("private_key.pem"):
                    if not self.load_key(self.password):
                        self.log_error("Incorrect password. Please log out and try again.")
                else:
                    self.generate_key_pair(self.password)
            else:
                self.log_error("Please set a strong password.")
                sys.exit(1)
        except Exception as e:
            self.log_error(f"An error occurred during key pair loading or generation: {str(e)}")

    def get_secure_password(self):
        password = simpledialog.askstring("Password Input", "Please enter your password: ", show='*')
        if self.is_strong_password(password):
            return password
        else:
            self.log_error("Please set a strong password.")
            return None

    def is_strong_password(self, password):
        if (
            len(password) >= 12 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]", password)
        ):
            return True
        return False

    def generate_key_pair(self, password):
        try:
            self.key = Fernet.generate_key()
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )

            with open("private_key.pem", "wb") as key_file:
                key_file.write(pem)

            self.private_key = private_key
            self.backup_key(password)
        except Exception as e:
            self.log_error(f"An error occurred during key pair generation: {str(e)}")
            sys.exit(1)

    def load_key(self, password):
        try:
            with open("private_key.pem", "rb") as key_file:
                pem = key_file.read()
                private_key = serialization.load_pem_private_key(
                    pem,
                    password=password.encode(),
                    backend=default_backend()
                )
            self.private_key = private_key
            return True
        except Exception as e:
            self.log_error(f"An error occurred while loading the private key: {str(e)}")
            return False

    def backup_key(self, password):
        try:
            if not os.path.exists(self.backup_dir):
                os.mkdir(self.backup_dir)

            key_backup_file = os.path.join(self.backup_dir, "private_key.pem")

            if os.path.exists(key_backup_file):
                os.remove(key_backup_file)

            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )

            with open(key_backup_file, "wb") as key_file:
                key_file.write(pem)
        except Exception as e:
            self.log_error(f"Backup failed: {str(e)}")

    def upload_file(self):
        try:
            file_path = filedialog.askopenfilename()
            if file_path:
                self.selected_file = file_path
                self.filename_label.config(text=f"Selected File: {file_path}")
                self.download_button.config(state=tk.NORMAL)
        except Exception as e:
            self.log_error(f"An error occurred during file upload: {str(e)}")

    def download_decrypted_file(self):
        try:
            with open(self.selected_file, 'rb') as file:
                data = file.read()
                if self.decrypt_and_verify(data):
                    self.log_message("File decrypted and verified successfully.")
                else:
                    self.log_error("Decryption or verification failed.")
        except Exception as e:
            self.log_error(f"An error occurred during file decryption: {str(e)}")

    def decrypt_and_verify(self, data):
        try:
            fernet = Fernet(self.key)
            decrypted_data = fernet.decrypt(data)
            output_folder = filedialog.askdirectory()
            if output_folder:
                filename = os.path.basename(self.selected_file)
                decrypted_file_path = os.path.join(output_folder, filename)
                with open(decrypted_file_path, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_data)
                return True
            else:
                self.log_error("Download canceled.")
                return False
        except Exception as e:
            self.log_error(f"An error occurred during decryption or verification: {str(e)}")
            return False

    def logout(self):
        self.password = None
        self.key = None
        self.private_key = None
        self.filename_label.config(text="")
        self.download_button.config(state=tk.DISABLED)
        self.log_message("Logged out. You can log in with a different password.")

    def log_message(self, message):
        self.logger.info(message)
        messagebox.showinfo("Success", message)

    def log_error(self, message):
        self.logger.error(message)
        messagebox.showerror("Error", "An error occurred. Please check the log for details.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileSecurityDefender(root)
    app.mainloop()
