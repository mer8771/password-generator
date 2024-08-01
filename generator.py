import secrets
import string
import re
import os
import tkinter as tk
from tkinter import messagebox, filedialog

# Check if the password has at least one uppercase letter, one lowercase letter, and one special character
def is_valid_password(password):
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_special = any(c in string.punctuation for c in password)
    return has_upper and has_lower and has_special

# Function to generate a random password with a given length
def generate_password(length):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

# Function to save password with name or site
def save_password(filepath, name, password):
    with open(filepath, "a") as file:
        file.write(f"{name}:      {password}\n")
        file.write("\n")
        file.write("\n")

# Function to validate URL
def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Function to handle button click
def on_generate_click():
    global save_path

    if not save_path:
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not save_path:
            return

    name = name_entry.get()
    if not is_valid_url(name):
        messagebox.showerror("Invalid URL", "Please enter a valid URL.")
        return

    try:
        password_length = int(length_entry.get())
        if password_length <= 4:
            messagebox.showerror("Invalid Length", "Password length must be greater than 4.")
            return
    except ValueError:
        messagebox.showerror("Invalid Length", "Please enter a valid number.")
        return
    
    # Load existing passwords
    try:
        with open(save_path) as file:
            existing_passwords = file.read().splitlines()
    except FileNotFoundError:
        existing_passwords = []

    # Generate a new password with duplicate checking
    while True:
        new_password = generate_password(password_length)
        if f"{name}: {new_password}" not in existing_passwords:
            save_password(save_path, name, new_password)
            break

    messagebox.showinfo("Password Saved", f"Password for {name} has been generated and saved.")

# Create main window
root = tk.Tk()
root.title("Password Manager")
root.geometry("500x300")
root.configure(bg='lightgray')

# Global variable to store the save path
save_path = None

# Create and place widgets
name_label = tk.Label(root, text="Enter the URL for the password:", fg='darkslateblue', bg='lightgray')
name_label.pack(pady=10)
name_entry = tk.Entry(root, width=50)
name_entry.pack(pady=10)

length_label = tk.Label(root, text="Enter password length:", fg='darkslateblue', bg='lightgray')
length_label.pack(pady=10)
length_entry = tk.Entry(root, width=20)
length_entry.pack(pady=10)

generate_button = tk.Button(root, text="Generate Password", fg='green', bg='black', command=on_generate_click)
generate_button.pack(pady=20)

# Run the application
root.mainloop()
