# cryptX - Secure Password Manager

**cryptX** is a secure, open-source password manager designed to help you generate, store, and retrieve passwords with ease. Built with encryption at its core, cryptX ensures your sensitive data is protected using the **Fernet symmetric encryption algorithm**. The tool features a user-friendly GUI powered by **Tkinter** and is compatible with Windows, macOS, and Linux.

## Features

- **Secure Encryption**: Passwords are encrypted using Fernet for maximum security.
- **Password Generation**: Generate strong, random passwords with customizable length.
- **Password Validation**: Ensure password strength with built-in validation rules.
- **Clipboard Integration**: Easily copy passwords to your clipboard for quick use.
- **User-Friendly GUI**: A clean and intuitive interface for seamless password management.

## Requirements

- Python 3.7 or later
- `cryptography` library
- `pyperclip` library
- `tkinter` (usually included with Python)

## Installation

1. Clone this repository:
   ```bash
   https://github.com/D4rkSynt4x/password_manager.git
   cd cryptx
   cd src
   

2.  Install the required dependencies
     ```bash
     pip install -r requirements.txt

3.  Launch cryptX
    ```bash
    python cryptX.py

Usage

1. Generate a Password
Click the "Generate Password" button.

Enter the desired password length (minimum 8 characters).

The generated password will be copied to your clipboard automatically.

2. Add a Password
Click the "Add Password" button.

Enter the account name, URL, and password (or leave blank to generate one).

The password will be securely stored in the encrypted database.

3. Retrieve a Password
Click the "Retrieve Password" button.

Enter the account name.

The password will be displayed and copied to your clipboard.

4. List All Accounts
Click the "List Accounts" button.

A list of all stored accounts will be displayed.

5. Clear All Passwords
Click the "Clear Passwords" button.

Enter the confirmation code 1234 to clear all passwords.

Contributing
Contributions are welcome! If you'd like to contribute to cryptX, please follow these steps:

Fork the repository.

Create a new branch for your feature or bugfix.

Submit a pull request with a detailed description of your changes.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Support

If you encounter any issues or have questions, feel free to open an issue on GitHub or contact the maintainer.
