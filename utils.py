import os
import pickle
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import messagebox
import sys


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS2
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def generate_encrypted_word(word, pattern):
    encrypted_word = ""
    pattern_length = len(pattern)
    pattern_index = 0

    for char in str(word):
        if char.isalpha():
            encrypted_char = chr((ord(char) - ord('A') + ord(pattern[pattern_index % pattern_length].upper()) - ord('A')) % 26 + ord('A')) if char.isupper() else chr((ord(char) - ord('a') + ord(pattern[pattern_index % pattern_length].lower()) - ord('a')) % 26 + ord('a'))
            encrypted_word += encrypted_char
            pattern_index += 1
        else:
            encrypted_word += char

    return encrypted_word


def decrypt_encrypted_word(encrypted_word, pattern):
    decrypted_word = ""
    pattern_length = len(pattern)
    pattern_index = 0

    for char in str(encrypted_word):
        if char.isalpha():
            decrypted_char = chr((ord(char) - ord(pattern[pattern_index % pattern_length].upper()) + 26) % 26 + ord('A')) if char.isupper() else chr((ord(char) - ord(pattern[pattern_index % pattern_length].lower()) + 26) % 26 + ord('a'))
            decrypted_word += decrypted_char
            pattern_index += 1
        else:
            decrypted_word += char

    return decrypted_word


def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)


import json

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode('utf-8'))


def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    except InvalidToken:
        messagebox.showerror("Error", "Invalid key")
        return None

def save_data(data, filename):
    if isinstance(data, dict):
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
    else:
        with open(filename, 'wb') as file:
            pickle.dump(data, file)


def load_data(filename):
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except (json.JSONDecodeError, UnicodeDecodeError):
        with open(filename, 'rb') as file:
            return pickle.load(file)


def is_main_password_exist(main_password_file):
    if not os.path.exists(main_password_file):
        return False
    else:
        return True

import random
import string

def generate_random_password(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
    """Generates a random password with customizable options."""
    characters = ""
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError("At least one character type must be selected.")

    return "".join(random.choice(characters) for _ in range(length))


def encrypt_files_in_directory(directory, stored_main_password_hash):

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)

        if os.path.isfile(file_path) and not filename.endswith('.encrypted'):
            output_file = file_path + '.encrypted'

            with open(file_path, 'rb') as file:
                data = file.read()

            encrypted_data = encrypt_data(data, stored_main_password_hash)

            with open(output_file, 'wb') as file:
                file.write(encrypted_data)

            os.remove(file_path)
    messagebox.showinfo('success','Encryption completed successfully.')

def decrypt_file(file_path, stored_main_password_hash):

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = decrypt_data(encrypted_data, stored_main_password_hash)

    decrypted_file_path = file_path[:-10]  # Remove the '.encrypted' extension
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    os.remove(file_path)

def list_files_in_directory(directory, file_name_listbox):
    file_name_listbox.delete(0, 'end')
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) and filename.endswith('.encrypted'):
            file_name_listbox.insert('end', filename)


def decrypt_selected_files(directory, selected_indices, stored_main_password_hash, file_name_listbox):
    num_files_decrypted = 0

    for index in selected_indices:
        file_name = file_name_listbox.get(index)
        file_path = os.path.join(directory, file_name)
        decrypt_file(file_path, stored_main_password_hash)
        num_files_decrypted += 1

    messagebox.showinfo("Decryption Status", f"{num_files_decrypted} file(s) decrypted successfully.")
    list_files_in_directory(directory, file_name_listbox)
