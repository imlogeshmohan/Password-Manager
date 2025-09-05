from flask import Flask, request, jsonify
from utils import (load_data, decrypt_data, encrypt_data, save_data, generate_key,
                   decrypt_encrypted_word, is_main_password_exist)
import os

app = Flask(__name__)

main_password_file = 'data/main_password.pickle'
data_file = 'data/password_data.pickle'
pattern = "453607"
salt, stored_main_password_hash = None, None

def load_main_password():
    global salt, stored_main_password_hash
    if is_main_password_exist(main_password_file):
        salt, encry_stored_main_password_hash = load_data(main_password_file)
        stored_main_password_hash = decrypt_encrypted_word(encry_stored_main_password_hash, pattern=pattern).encode()

@app.route('/login', methods=['POST'])
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

@app.route('/passwords', methods=['GET'])
def get_passwords():
    try:
        encrypted_password_data = str(load_data(data_file))
        saved_data = encrypted_password_data.split(",")
        passwords = []
        for item in saved_data:
            website, encrypted_credential = item.split('@')
            decrypted_credential = decrypt_data(encrypted_credential.encode(), stored_main_password_hash)
            username, password = decrypted_credential.split(',')
            passwords.append({"website": website, "username": username, "password": password})
        return jsonify(passwords), 200
    except FileNotFoundError:
        return jsonify([]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/passwords', methods=['POST'])
def add_password():
    data = request.get_json()
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')

    if not all([website, username, password]):
        return jsonify({"error": "Website, username, and password are required"}), 400

    encrypted_credential = encrypt_data(f"{username},{password}", stored_main_password_hash).decode()
    new_entry = f"{website.lower()}@{encrypted_credential}"

    try:
        if os.path.exists(data_file):
            existing_data = str(load_data(data_file))
            save_data(f"{existing_data},{new_entry}", data_file)
        else:
            save_data(new_entry, data_file)
        return jsonify({"message": "Password added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    load_main_password()
    app.run(port=5000)
