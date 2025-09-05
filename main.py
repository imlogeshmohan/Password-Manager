import os
import threading
import json
from flask import Flask, request, jsonify
from ui import PasswordManagerUI
import customtkinter
from utils import (load_data, decrypt_data, encrypt_data, save_data, generate_key,
                   decrypt_encrypted_word, is_main_password_exist)

# --- Flask App ---
flask_app = Flask(__name__)

main_password_file = 'data/main_password.pickle'
data_file = 'data/password_data.json'
pattern = "453607"
salt, stored_main_password_hash = None, None

def load_main_password():
    global salt, stored_main_password_hash
    if is_main_password_exist(main_password_file):
        salt, encry_stored_main_password_hash = load_data(main_password_file)
        stored_main_password_hash = decrypt_encrypted_word(encry_stored_main_password_hash, pattern=pattern).encode()

@flask_app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    master_password = data.get('master_password')

    if not master_password:
        return jsonify({"error": "Master password is required"}), 400

    if not stored_main_password_hash:
        return jsonify({"error": "Main password not set up in the desktop app"}), 400

    main_password_hash = generate_key(master_password, salt)

    if main_password_hash == stored_main_password_hash:
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Incorrect master password"}), 401

@flask_app.route('/passwords', methods=['GET'])
def get_passwords():
    try:
        with open(data_file, 'r') as f:
            password_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        password_data = {}

    passwords = []
    for website, encrypted_credential in password_data.items():
        decrypted_credential = decrypt_data(encrypted_credential.encode('utf-8'), stored_main_password_hash)
        if decrypted_credential:
            username = decrypted_credential['username']
            password = decrypted_credential['password']
            passwords.append({"website": website, "username": username, "password": password})

    return jsonify(passwords), 200


@flask_app.route('/passwords', methods=['POST'])
def add_password():
    data = request.get_json()
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')

    if not all([website, username, password]):
        return jsonify({"error": "Website, username, and password are required"}), 400

    try:
        with open(data_file, 'r') as f:
            password_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        password_data = {}

    new_entry = {"username": username, "password": password}
    encrypted_entry = encrypt_data(new_entry, stored_main_password_hash)
    password_data[website.lower()] = encrypted_entry.decode('utf-8')

    with open(data_file, 'w') as f:
        json.dump(password_data, f, indent=4)

    return jsonify({"message": "Password added successfully"}), 201

def run_flask_app():
    load_main_password()
    flask_app.run(port=5000)

# --- Customtkinter App ---
def main():
    pattern = "453607"

    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists('data/files'):
        os.makedirs('data/files')

    if os.path.exists(main_password_file):
        salt, _ = load_data(main_password_file)
    else:
        salt = os.urandom(16)


    # Run Flask app in a separate thread
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    customtkinter.set_appearance_mode("System")
    customtkinter.set_default_color_theme("blue")
    
    app = PasswordManagerUI(data_file, main_password_file, salt, pattern)
    app.mainloop()

if __name__ == "__main__":
    main()
