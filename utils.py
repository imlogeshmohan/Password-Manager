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


def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(pickle.dumps(data))
    return encrypted_data


def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    try:
        data = pickle.loads(f.decrypt(encrypted_data))
        return data
    except InvalidToken:
        messagebox.showerror("Error","Invalid key")

def save_data(data, filename):
    with open(filename, 'wb') as file:
        pickle.dump(data, file)


def load_data(filename):
    with open(filename, 'rb') as file:
        data = pickle.load(file)
    return data


def is_main_password_exist(main_password_file):
    if not os.path.exists(main_password_file):
        return False
    else:
        return True

def generate_password(website_entry, username_entry, password_entry):
    website = website_entry.get()
    username  = username_entry.get()

    if not website or not username:
            messagebox.showerror("Error", "Please enter website and username.")
            return

    website = str(website).replace(" ","")
    # Repeat the username until it reaches a length of 6 characters
    while len(username) < 6:
        username += username

    # Repeat the website name until it reaches a length of 6 characters
    while len(website) < 6:
        website += website

    # Take the first 6 characters of the username and website
    username = username[:6]
    website = website[:6]

    # Extract the second letter of the password
    second_letter = website[1].lower()

    my_list = [
        "apple", "ball", "cat", "dog", "elephant", "frog", "goat", "hat", "ink", "jacket",
        "key", "lion", "mouse", "nest", "orange", "pen", "queen", "ring", "snake", "table",
        "umbrella", "vase", "watch", "x-ray", "yo-yo", "zebra"
    ]

    second_letter_word = ""
    for word in my_list:
        if word[0].lower() == second_letter.lower():
            second_letter_word = word

    while len(second_letter_word) < 4:
        second_letter_word += second_letter_word

    # Extract the numerical representation of the second letter
    second_letter_number = ord(second_letter) - 96

    if second_letter_number < 10:
        second_letter_number = "0" + str(second_letter_number)

    second_pass_word = f"LOGU{website[:2]}".upper() if int(second_letter_number) % 2 == 0 else f"LOGX{website[:2]}".upper()

    # Create the password
    password = f"{website}@{second_pass_word}#{second_letter_word}{second_letter_number}"

    # Adjust the password length to 20 characters
    if len(password) < 20:
        password += "!" * (20 - len(password))

    password_entry.delete(0, 'end')
    password_entry.insert(0, password)


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
