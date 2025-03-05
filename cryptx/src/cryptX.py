import random
import string
import json
import os
from cryptography.fernet import Fernet  # Import Fernet for encryption
try:
    import tkinter as tk
    from tkinter import messagebox, simpledialog
except ImportError:
    # Error if tkinter is not installed or available in the environment
    raise ImportError("The tkinter module is required but not installed. Please install tkinter (e.g., 'sudo apt-get install python3-tk' on Linux).")
import pyperclip
from typing import IO


class PasswordManager:
    """
    Handles all password-related operations such as adding, retrieving, 
    encrypting, decrypting, and storing passwords.
    """

    def __init__(self, storage_file="passwords.json"):
        """
        Initialize the PasswordManager object.

        Args:
            storage_file (str): Path to the password storage file.
        """
        self.storage_file = storage_file
        # Location to store the encryption key
        self.key_file = os.path.expanduser("~/.config/cryptx/key.key")
        # Load or generate the encryption key
        self.key = self.load_or_generate_key()
        # Load the existing passwords (decrypt if encrypted)
        self.passwords = self.load_passwords()

    def load_or_generate_key(self):
        """
        Load an existing encryption key or generate a new one.

        Returns:
            bytes: The encryption key.
        """
        try:
            # Ensure the directory for the key file exists
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
        except PermissionError:
            # Handle permission issues during directory creation
            raise PermissionError("Failed to create the directory for the encryption key. Ensure you have sufficient permissions.")
        
        # If the key file doesn't exist, generate a new encryption key
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
        else:
            # Otherwise, load the existing key
            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
        return key

    def encrypt_data(self, data):
        """
        Encrypt a string using the encryption key.

        Args:
            data (str): The string to encrypt.

        Returns:
            bytes: The encrypted data.
        """
        fernet = Fernet(self.key)
        return fernet.encrypt(data.encode())

    def decrypt_data(self, data):
        """
        Decrypt encrypted data using the encryption key.

        Args:
            data (bytes): The encrypted data.

        Returns:
            str: The decrypted string.
        """
        fernet = Fernet(self.key)
        return fernet.decrypt(data).decode()

    def load_passwords(self):
        """
        Load and decrypt passwords from the storage file.

        Returns:
            dict: A dictionary containing account-password mappings.
        """
        if os.path.exists(self.storage_file):
            try:
                # Open the file and read the encrypted data
                with open(self.storage_file, "rb") as file:
                    encrypted_data = file.read()
                    try:
                        # Attempt to decrypt the data
                        decrypted_data = self.decrypt_data(encrypted_data)
                        return json.loads(decrypted_data)
                    except Exception:
                        # Handle plain-text JSON files (migrate to encrypted format)
                        file.seek(0)  # Reset file pointer
                        passwords = json.load(file)
                        self.save_passwords(passwords)  # Encrypt and save
                        return passwords
            except (json.JSONDecodeError, ValueError):
                # Return an empty dictionary if the file is corrupted or invalid
                return {}
        return {}

    def save_passwords(self, passwords=None):
        """
        Encrypt and save passwords to the storage file.

        Args:
            passwords (dict): The passwords dictionary to save. Defaults to `self.passwords`.
        """
        try:
            if passwords is None:
                passwords = self.passwords
            encrypted_data = self.encrypt_data(json.dumps(passwords))
            with open(self.storage_file, "wb") as file:
                file.write(encrypted_data)
        except IOError as e:
            print(f"Error saving passwords: {e}")

    @staticmethod
    def generate_password(length=16):
        """
        Generate a random password of a specified length.

        Args:
            length (int): The length of the password.

        Returns:
            str: The generated password.
        """
        if length < 8:
            raise ValueError("Password length should be at least 8 characters for security.")
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    @staticmethod
    def validate_password(password):
        """
        Validate the strength of a given password.

        Args:
            password (str): The password to validate.

        Returns:
            tuple: (bool, str) Validation result and message.
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not any(char.isupper() for char in password):
            return False, "Password must contain at least one uppercase letter."
        if not any(char.islower() for char in password):
            return False, "Password must contain at least one lowercase letter."
        if not any(char.isdigit() for char in password):
            return False, "Password must contain at least one number."
        if not any(char in string.punctuation for char in password):
            return False, "Password must contain at least one special character."
        return True, "Password is valid."

    def add_password(self, account, url, password):
        """
        Add a password for an account.

        Args:
            account (str): The account name.
            url (str): The account URL.
            password (str): The password.
        """
        self.passwords[account.lower()] = {"url": url, "password": password}
        self.save_passwords()

    def retrieve_password(self, account):
        """
        Retrieve a password by account name.

        Args:
            account (str): The account name.

        Returns:
            dict: The account details or None if not found.
        """
        return self.passwords.get(account.lower(), None)

    def list_accounts(self):
        """
        List all stored accounts.

        Returns:
            list: A list of account names.
        """
        return list(self.passwords.keys())

    def clear_passwords(self):
        """
        Clear all stored passwords.
        """
        self.passwords = {}
        self.save_passwords()


class CryptxApp:
    """
    The main GUI application for managing passwords using Tkinter.
    """

    def __init__(self, root):
        """
        Initialize the GUI application.

        Args:
            root (tk.Tk): The root Tkinter window.
        """
        self.manager = PasswordManager()
        self.root = root

        # Window properties
        self.root.title("Cryptx")
        self.root.geometry("350x500")
        self.root.configure(bg="#8531d0")
        self.root.resizable(False, False)

        # Set the window icon
        icon_path = r"C:\Users\Moshin\OneDrive\Desktop\passman\cryptx\assets\crypticon.ico"
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception as e:
                print(f"Error loading icon: {e}")
        else:
            print("Warning: Icon file not found. Using default window icon.")

        # Add title label
        self.label_title = tk.Label(
            root, text="Cryptx", font=("Georgia", 20, "bold"), fg="#5be753", bg="#8531d0"
        )
        self.label_title.pack(pady=15)

        # Frame for buttons
        self.frame = tk.Frame(root, bg="#8531d0")
        self.frame.pack(expand=True, fill="both", pady=10)

        # Define button styles
        button_style = {
            "bg": "#3A3D5C",
            "fg": "white",
            "font": ("Georgia", 12),
            "relief": "flat",
            "highlightbackground": "yellow",
            "highlightthickness": 2,
            "bd": 3,
            "width": 18,
            "height": 1,
        }

        # Add buttons to the frame
        self.button_generate = tk.Button(
            self.frame, text="Generate Password", command=self.generate_password, **button_style
        )
        self.button_generate.pack(pady=8)

        self.button_add = tk.Button(
            self.frame, text="Add Password", command=self.add_password, **button_style
        )
        self.button_add.pack(pady=8)

        self.button_retrieve = tk.Button(
            self.frame, text="Retrieve Password", command=self.retrieve_password, **button_style
        )
        self.button_retrieve.pack(pady=8)

        self.button_list = tk.Button(
            self.frame, text="List Accounts", command=self.list_accounts, **button_style
        )
        self.button_list.pack(pady=8)

        # Button for clearing passwords with a warning style
        button_style_clear = button_style.copy()
        button_style_clear["bg"] = "#ff4c33"
        self.button_clear = tk.Button(
            self.frame, text="Clear Passwords", command=self.clear_passwords, **button_style_clear
        )
        self.button_clear.pack(pady=8)

    def safe_copy_to_clipboard(self, text):
        """
        Safely copy text to the clipboard.

        Args:
            text (str): The text to copy.
        """
        try:
            pyperclip.copy(text)
        except pyperclip.PyperclipException as e:
            messagebox.showwarning("Clipboard Error", f"Failed to copy to clipboard: {e}")

    def generate_password(self):
        """
        Generate and display a random password.
        """
        try:
            length = simpledialog.askinteger(
                "Password Length",
                "Enter the desired password length (minimum 8):",
                minvalue=8,
                parent=self.root,
            )
            if length:
                password = self.manager.generate_password(length)
                self.safe_copy_to_clipboard(password)
                messagebox.showinfo("Generated Password", f"Password: {password}\n\nCopied to clipboard!")
        except ValueError as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    def add_password(self):
        """
        Add a new password to the manager.
        """
        account = simpledialog.askstring("Account Name", "Enter the account/app name:", parent=self.root)
        if not account:
            return
        url = simpledialog.askstring("Account URL", "Enter the account/app URL:", parent=self.root)
        if not url:
            return
        password = simpledialog.askstring("Password", "Enter the password (or leave blank to generate):", parent=self.root)
        if password is None:
            return
        if not password:
            password = self.manager.generate_password()
            self.safe_copy_to_clipboard(password)
            messagebox.showinfo("Generated Password", f"Generated Password: {password}\n\nCopied to clipboard!")
        else:
            valid, message = self.manager.validate_password(password)
            if not valid:
                messagebox.showerror("Invalid Password", message, parent=self.root)
                return
        self.manager.add_password(account, url, password)
        messagebox.showinfo("Success", f"Password for '{account}' added successfully!", parent=self.root)

    def retrieve_password(self):
        """
        Retrieve and display a password by account name.
        """
        account = simpledialog.askstring("Retrieve Password", "Enter the account/app name:", parent=self.root)
        if account:
            data = self.manager.retrieve_password(account)
            if data:
                self.safe_copy_to_clipboard(data["password"])
                messagebox.showinfo(
                    "Password Retrieved",
                    f"Account: {account}\nURL: {data['url']}\nPassword: {data['password']}\n\nPassword copied to clipboard!",
                    parent=self.root,
                )
            else:
                messagebox.showerror("Error", f"No password found for '{account}'.", parent=self.root)

    def list_accounts(self):
        """
        List all stored accounts.
        """
        accounts = self.manager.list_accounts()
        if accounts:
            accounts_list = "\n".join(accounts)
            messagebox.showinfo("Stored Accounts", f"Accounts:\n{accounts_list}", parent=self.root)
        else:
            messagebox.showinfo("Stored Accounts", "No accounts stored.", parent=self.root)

    def clear_passwords(self):
        """
        Clear all stored passwords after confirmation.
        """
        confirmation = simpledialog.askstring(
            "Clear All Passwords", "Enter '1234' to confirm clearing all passwords:", parent=self.root
        )
        if confirmation == "1234":
            self.manager.clear_passwords()
            messagebox.showinfo("Success", "All passwords and accounts have been cleared.", parent=self.root)
        else:
            messagebox.showerror("Error", "Incorrect confirmation code. No data was cleared.", parent=self.root)


if __name__ == "__main__":
    # Start the GUI application
    root = tk.Tk()
    app = CryptxApp(root)
    root.mainloop()
