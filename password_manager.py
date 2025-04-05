import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from getpass import getpass
import base64
import string
import secrets

# Configuration
DATA_FILE = 'passwords.enc'
SALT_FILE = 'salt.bin'
MASTER_PASSWORD_PROMPT = "Enter your master password: "

def load_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as f:
            return f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
        return salt

def derive_key(password: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=load_salt(),
        iterations=100_000
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_data(data: dict, key: bytes) -> None:
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    with open(DATA_FILE, 'wb') as f_out:
        f_out.write(encrypted_data)

def decrypt_data(key: bytes) -> dict:
    if not os.path.exists(DATA_FILE):
        return {}
    
    f = Fernet(key)
    try:
        with open(DATA_FILE, 'rb') as f_in:
            encrypted_data = f_in.read()
        decrypted_data = json.loads(f.decrypt(encrypted_data))
        return decrypted_data
    except InvalidToken:
        print("Invalid master password. Please try again.")
        exit(1)

def get_master_password() -> bytes:
    password = getpass(MASTER_PASSWORD_PROMPT).encode()
    key = derive_key(password)
    return key

def generate_password(length: int = 16) -> str:
    if length < 6:
        raise ValueError("Password length must be at least 6 characters.")
    
    # Ensure the password contains at least one of each required character type
    while True:
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation)
                           for _ in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)):
            return password

def main():
    key = get_master_password()
    
    while True:
        print("\nPassword Manager")
        print("1. Add a new website and generate a password")
        print("2. Retrieve passwords for all websites")
        print("3. Delete a website")
        print("4. Generate a password for an existing website")
        print("5. Exit")
        
        choice = input("Enter your choice: ").strip()
        
        if choice == '1':
            website = input("Enter the new website name: ").strip()
            data = decrypt_data(key)
            
            if website in data:
                print(f"Website '{website}' already exists. Please use option 4 to generate a new password for it.")
                continue
            
            password = generate_password()
            data[website] = password
            encrypt_data(data, key)
            print(f"New password generated and added for '{website}': {password}")
        
        elif choice == '2':
            data = decrypt_data(key)
            if not data:
                print("No websites stored.")
            else:
                print("\nStored Websites and Passwords:")
                for website, password in data.items():
                    print(f"Website: {website}, Password: {password}")
        
        elif choice == '3':
            website = input("Enter the website to delete: ").strip()
            data = decrypt_data(key)
            
            if website not in data:
                print(f"Website '{website}' not found.")
            else:
                del data[website]
                encrypt_data(data, key)
                print(f"Website '{website}' deleted successfully.")
        
        elif choice == '4':
            website = input("Enter the website to generate a new password for: ").strip()
            data = decrypt_data(key)
            
            if website not in data:
                print(f"Website '{website}' not found. Please use option 1 to add it.")
            else:
                password = generate_password()
                data[website] = password
                encrypt_data(data, key)
                print(f"New password generated and associated with '{website}': {password}")
        
        elif choice == '5':
            print("Exiting the password manager. Goodbye!")
            break
        
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()