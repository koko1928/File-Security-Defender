import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import base64
import shutil
import logging
import re
import sys

class FileSecurityDefender:
    def __init__(self, root):
        self.root = root
        self.root.title("File Security Defender")
        self.password = None
        self.selected_file = None
        self.salt = None
        self.key = None
        self.backup_dir = "key_backup"

        self.setup_logging()
        self.logger = logging.getLogger(__name)

        self.setup_ui()
        self.load_or_generate_key_pair()

    def setup_logging(self):
        log_filename = "app.log"
        logging.basicConfig(filename=log_filename, level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    def setup_ui(self):
        self.upload_button = tk.Button(self.root, text="Upload File", command=self.upload_file)
        self.upload_button.pack()

        self.encrypt_button = tk.Button(self.root, text="Encrypt File", state=tk.DISABLED, command=self.encrypt_file)
        self.encrypt_button.pack()

        self.sign_button = tk.Button(self.root, text="Sign File", state=tk.DISABLED, command=self.sign_file)
        self.sign_button.pack()

        self.download_button = tk.Button(self.root, text="Download File", state=tk.DISABLED, command=self.download_file)
        self.download_button.pack()

        self.filename_label = tk.Label(self.root, text="")
        self.filename_label.pack()

    def load_or_generate_key_pair(self):
        try:
            self.password = self.get_secure_password()
            if self.password:
                if os.path.exists("private_key.pem"):
                    self.load_key(self.password)
                else:
                    self.generate_key_pair(self.password)
            else:
                self.log_error("Please set a strong password.")
                sys.exit(1)

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
            self.salt = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                iterations=100000,
                salt=self.salt,
                length=32
            )
            self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.key)
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
                private_key = load_pem_private_key(
                    pem,
                    password=password.encode(),
                    backend=default_backend()
                )
            self.private_key = private_key
        except Exception as e:
            self.log_error(f"An error occurred while loading the private key: {str(e)}")
            sys.exit(1)

    def backup_key(self, password):
        try:
            if not os.path.exists(self.backup_dir):
                os.mkdir(self.backup_dir)

            key_backup_file = os.path.join(self.backup_dir, "private_key.pem")

            if os.path.exists(key_backup_file):
                os.remove(key_backup_file)

            shutil.copy("private_key.pem", key_backup_file)

            with open(key_backup_file, "rb") as key_file:
                pem = key_file.read()
                private_key = load_pem_private_key(
                    pem,
                    password=password.encode(),
                    backend=default_backend()
                )
                encryption_algorithm = serialization.BestAvailableEncryption(self.key)
                pem = private_key.private_bytes(
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
                self.encrypt_button.config(state=tk.NORMAL)
        except Exception as e:
            self.log_error(f"An error occurred during file upload: {str(e)}")

    def encrypt_file(self):
        try:
            with open(self.selected_file, 'rb') as file:
                data = file.read()
                fernet = Fernet(self.key)
                encrypted_data = fernet.encrypt(data)
                with open(self.selected_file, 'wb') as encrypted_file:
                    encrypted_file.write(encrypted_data)
                self.sign_button.config(state=tk.NORMAL)
        except Exception as e:
            self.log_error(f"An error occurred during file encryption: {str(e)}")

    def sign_file(self):
        try:
            with open(self.selected_file, 'rb') as file:
                data = file.read()
                signature = self.private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                with open(self.selected_file, 'ab') as file:
                    file.write(signature)
                self.download_button.config(state=tk.NORMAL)
        except Exception as e:
            self.log_error(f"An error occurred during file signing: {str(e)}")

    def download_file(self):
        try:
            with open(self.selected_file, 'rb') as file:
                data = file.read()
                if self.verify_signature(data[:-256], data[-256:]):
                    fernet = Fernet(self.key)
                    decrypted_data = fernet.decrypt(data[:-256])
                    output_folder = filedialog.askdirectory()
                    if output_folder:
                        filename = os.path.basename(self.selected_file)
                        decrypted_file_path = os.path.join(output_folder, filename)
                        with open(decrypted_file_path, 'wb') as decrypted_file:
                            decrypted_file.write(decrypted_data)
                        self.log_message("File downloaded successfully.")
                    else:
                        self.log_error("Download canceled.")
                else:
                    self.log_error("Signature verification failed.")
        except Exception as e:
            self.log_error(f"An error occurred during file download: {str(e)}")

    def verify_signature(self, data, signature):
        try:
            self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def log_message(self, message):
        self.logger.info(message)
        messagebox.showinfo("Success", message)

    def log_error(self, message):
        self.logger.error(message)
        messagebox.showerror("Error", message)

    def mainloop(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileSecurityDefender(root)
    app.mainloop()
