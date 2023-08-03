import tkinter as tk
from tkinter import BOTH, Canvas,LEFT, RIGHT, Y , X , VERTICAL
import ttkbootstrap as ttk
import os
import pickle
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import clipboard
from tkinter import messagebox
from PIL import ImageTk, Image
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


def set_label1_text(main_password_file):
    if not os.path.exists(main_password_file):
        label1_var.set("Create a main password: ")
    else:
        label1_var.set("Enter main password")


def is_main_password_exist():
    if not os.path.exists(main_password_file):
        return False
    else:
        return True


def setup_main_password(main_password_file, salt, pattern):
    main_password = password_var.get()
    main_password_hash = generate_key(main_password, salt)
    encry_main_password_hash = generate_encrypted_word(main_password_hash.decode(), pattern= pattern)  # add your own pattern
    save_data((salt, encry_main_password_hash), main_password_file)
    messagebox.showinfo("success","Password saved successfully.")
    password_var.set("")
    set_label1_text(main_password_file)



def update_data_with_new_key(data_file, old_key, new_key):
    if os.path.exists(data_file):
        encrypted_password_data = str(load_data(data_file))
        saved_data = encrypted_password_data.split(",")

        new_encrypted_data = []

        for data in saved_data:
            credential = data.split("@")
            decrypted_data = str(decrypt_data(credential[1].encode(), old_key))
            new_encrypted_data.append(f"{credential[0]}@{encrypt_data(decrypted_data, new_key).decode()}")

        save_data(",".join(new_encrypted_data), data_file)

    directory = "data/files"

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) and filename.endswith('.encrypted'):
            file_path = os.path.join(directory, filename)
            # decrypt_file(file_path, old_key)
            with open(file_path, "rb") as file:
                encrypt_file_data = file.read()
            
            decrypted_data = decrypt_data(encrypt_file_data, old_key)

            new_encrypt_data = encrypt_data(decrypted_data, new_key)

            with open(file_path, 'wb') as file:
                file.write(new_encrypt_data)



def main_password_checker(main_password_file, output_label , pattern):
    label1_var.set("Enter main password")
    salt, encry_stored_main_password_hash = load_data(main_password_file)
    stored_main_password_hash = decrypt_encrypted_word(encry_stored_main_password_hash, pattern=pattern).encode()

    main_password = password_var.get()
    main_password_hash = generate_key(main_password, salt)

    if main_password_hash == stored_main_password_hash:
        output_var.set("Logging successful")
        display_main_menu(data_file, stored_main_password_hash, salt, main_password_file)
        return
    else:
        output_var.set("Incorrect password")
        output_label.after(2000, lambda: output_var.set(""))
        return  # Exit the function after updating the output_var



def display_main_menu(data_file, stored_main_password_hash, salt, main_password_file):
    clear_window()

    menu_frame = ttk.Frame(master=window)
    menu_frame.pack(pady=30)
    
    menu_lable = ttk.Label(master= menu_frame, text = "Menu", font=("Helvetica", 14))
    menu_lable.pack(pady=10)

    options = [
        ("Create new credential", generate_password_menu),
        ("Display saved passwords", load_password),
        ("Edit saved password", edit_saved_password_menu),
        ("Delete saved password", delete_saved_credentials),
        ("Change main password", display_change_password),
        ("Encrypt file", encrypt_files_in_directory),
        ("Decrypt file", decrypt_files_in_directory)
    ]

    option_buttons = []
    for option_text, option_command in options:
        button = ttk.Button(master=menu_frame, text=option_text, width=30,
                            command=lambda cmd=option_command: cmd(data_file, stored_main_password_hash, output_label, main_password_file, salt))
        button.pack(pady=5)
        option_buttons.append(button)

    output_label = ttk.Label(master=menu_frame, text="", font=("Helvetica", 12))
    output_label.pack(pady=10)

    window.bind("<Up>", lambda event: move_selection(-1, option_buttons))
    window.bind("<Down>", lambda event: move_selection(1, option_buttons))
    window.bind("<Return>", lambda event: handle_option(data_file, stored_main_password_hash, salt,main_password_file, get_selected_option(option_buttons),output_label=output_label))


def clear_window():
    for child in window.winfo_children():
        child.destroy()


def move_selection(direction, option_buttons):
    current_index = get_selected_option(option_buttons)
    if current_index is not None:
        next_index = (current_index + direction) % len(option_buttons)
        option_buttons[next_index].focus()


def get_selected_option(option_buttons):
    for index, button in enumerate(option_buttons):
        if button == window.focus_get():
            return index
    return None


def handle_option(data_file, stored_main_password_hash, salt, main_password_file, option_index, output_label):
    if option_index == 0:
        generate_password_menu(data_file, stored_main_password_hash, output_label)
    elif option_index == 1:
        load_password(data_file, stored_main_password_hash, output_label)
    elif option_index == 2:
        edit_saved_password_menu(data_file, stored_main_password_hash, output_label)
    elif option_index == 3:
        delete_saved_credentials(data_file, stored_main_password_hash, output_label, main_password_file, salt)
    elif option_index == 4:
        display_change_password(data_file, stored_main_password_hash, output_label, main_password_file, salt)
        output_label.config(text="Closing program to apply changes.")
    elif option_index == 5:
        encrypt_files_in_directory(data_file, stored_main_password_hash, output_label, main_password_file, salt)
    elif option_index == 6:
        decrypt_files_in_directory(data_file, stored_main_password_hash, output_label, main_password_file, salt)
        # window.after(2000, window.destroy)


    
def save_password(website_entry, username_entry, password_entry, data_file, stored_main_password_hash, output_label):
    website = website_entry.get().lower()
    username = username_entry.get()
    password = password_entry.get()

    encrypted_data = encrypt_data(f"{username},{password}", stored_main_password_hash).decode()
    if not os.path.exists(data_file):
        save_data(f"{website}@{encrypted_data}", data_file)
    else:
        encrypt_password_data = load_data(data_file)
        save_data(f"{encrypt_password_data},{website}@{encrypted_data}", data_file)
    
    messagebox.showinfo("Success", "Changes have been saved successfully!")

    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

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

    password_entry.insert(0, password)
    clipboard.copy(password)

def generate_password_menu(data_file, stored_main_password_hash, output_label, *args):
    # Implementation for creating new credential

    def save_changes(website_entry, username_entry, password_entry, data_file, stored_main_password_hash, output_label):
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return
        
        save_password(website_entry, username_entry, password_entry, data_file, stored_main_password_hash, output_label)
        

    clear_window()


    label_main = tk.Label(window, text="Create credential", font=(18))
    label_main.pack(pady=40)

    main_fram = tk.Frame(master=window)
    main_fram.pack()

    website_label = tk.Label(main_fram, text="Website:", font=(10))
    website_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky=tk.E)
    website_entry = tk.Entry(main_fram, width=30)
    website_entry.grid(row=0, column=1, padx=10, pady=(10, 5), sticky=tk.W)

    username_label = tk.Label(main_fram, text="Username:", font=(10))
    username_label.grid(row=1, column=0, padx=10, pady=(0, 5), sticky=tk.E)
    username_entry = tk.Entry(main_fram, width=30)
    username_entry.grid(row=1, column=1, padx=10, pady=(0, 5), sticky=tk.W)

    password_label = tk.Label(main_fram, text="Password:", font=(10))
    password_label.grid(row=2, column=0, padx=10, pady=(0, 5), sticky=tk.E)
    password_entry = tk.Entry(main_fram, width=30)
    password_entry.grid(row=2, column=1, padx=10, pady=(0, 5), sticky=tk.W)

    button_frame = tk.Frame(main_fram)
    button_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=30)

    generate_button = tk.Button(button_frame, text="Generate", width=10, command=lambda: generate_password(website_entry, username_entry, password_entry))
    generate_button.grid(row=0, column=0, padx=5)

    save_button = tk.Button(button_frame, text="Save", width=10, command=lambda: save_changes(website_entry, username_entry, password_entry, data_file, stored_main_password_hash, output_label))
    save_button.grid(row=0, column=1, padx=5)

    back_button = ttk.Button(button_frame, text="Go Back", width=10, command=lambda: display_main_menu(data_file, stored_main_password_hash, salt, output_label))
    back_button.grid(row=0, column=2, padx=5)



def clear_window():
    for child in window.winfo_children():
        child.destroy()


def load_password(data_file, stored_main_password_hash, output_label, *args):
    clear_window()

    encrypted_password_data = str(load_data(data_file))
    saved_data = encrypted_password_data.split(",")
    websites = []

    save_menu_frame = ttk.Frame(master=window)
    save_menu_frame.pack(pady=20)

    label = ttk.Label(save_menu_frame, text="Available credentials", font=(18))
    label.pack(pady=(20, 30))  # Added top padding

    scrollable_frame = ttk.Frame(save_menu_frame)
    scrollable_frame.pack(fill='both', expand=True)

    # Create a scrollable area
    canvas = tk.Canvas(scrollable_frame)
    canvas.pack(side='left', fill='both', expand=True)

    scrollbar = ttk.Scrollbar(scrollable_frame, orient="vertical", command=canvas.yview)
    scrollbar.pack(side='right', fill='y')

    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
    canvas.bind("<MouseWheel>", lambda event: canvas.yview_scroll(int(-1 * (event.delta / 120)), "units"))  # Enable scrolling with touchpad

    scrollable_area = ttk.Frame(canvas)
    canvas.create_window((0, 0), window=scrollable_area, anchor='nw')

    # Find the length of the longest website name
    longest_name_length = max(len(data.split("@")[0].capitalize()) for data in saved_data)

    for x in saved_data:
        data = x.split("@")
        if len(data) >= 2:
            websites.append([data[0], data[1]])
            if longest_name_length <= 10:
                multiplier = 14
            elif longest_name_length <= 15:
                multiplier = 12
            elif longest_name_length <= 25:
                multiplier = 4
            else:
                multiplier = 7
            padx_value = (longest_name_length * multiplier, 20)
            button = ttk.Button(scrollable_area, text=data[0].capitalize(), command=lambda website=data[0]: display_credentials(website, websites, stored_main_password_hash, output_label))
            button.pack(fill='x', padx=padx_value, pady=5, anchor='center')  # Center the button within the scrollable_area

    # Update the scrollable area after adding buttons
    scrollable_area.update_idletasks()
    canvas.configure(scrollregion=canvas.bbox('all'))

    back_button = ttk.Button(save_menu_frame, text="Go Back", command=lambda: display_main_menu(data_file, stored_main_password_hash, salt, main_password_file))
    back_button.pack(pady=5)




def display_credentials(website, websites, stored_main_password_hash, output_label):
    clear_window()

    website_data = None
    for site in websites:
        if site[0].lower() == website.lower():
            website_data = site[1]
            break

    if website_data:
        decrypted_data = decrypt_data(website_data.encode(), stored_main_password_hash)
        if decrypted_data:
            username, password = decrypted_data.split(",")

            # Create copy button icons
            copy_username_icon = ImageTk.PhotoImage(Image.open(resource_path("asset\\copy_icon.png")))
            copy_password_icon = ImageTk.PhotoImage(Image.open(resource_path("asset\\copy_icon.png")))

            label = ttk.Label(window, text= str(website).capitalize(), font=(24))
            label.pack(pady=50)

            # Username label and copy button
            username_frame = ttk.Frame(window)
            username_frame.pack(pady=5)

            username_label = ttk.Label(username_frame, text="Username: " + username)
            username_label.pack(side=LEFT, padx=(0, 10))

            copy_username_button = ttk.Button(username_frame, image=copy_username_icon, command=lambda: clipboard.copy(username), style="IconButton.TButton")
            copy_username_button.image = copy_username_icon
            copy_username_button.pack(side=LEFT)

            # Password label and copy button
            password_frame = ttk.Frame(window)
            password_frame.pack(pady=5)

            password_label = ttk.Label(password_frame, text="Password: " + password)
            password_label.pack(side=LEFT, padx=(0, 10))

            copy_password_button = ttk.Button(password_frame, image=copy_password_icon, command=lambda: clipboard.copy(password), style="IconButton.TButton")
            copy_password_button.image = copy_password_icon
            copy_password_button.pack(side=LEFT)


            back_button = ttk.Button(window, text="Go Back", command=lambda: load_password(data_file, stored_main_password_hash, output_label))
            back_button.pack(pady=5)

        else:
            error_label = ttk.Label(window, text="Invalid key. Please close the program and retry.")
            error_label.pack(pady=10)
    else:
        error_label = ttk.Label(window, text="Sorry, credentials for " + website + " not found.")
        error_label.pack(pady=10)


def change_main_password(data_file, stored_main_password_hash, output_label, current_password_entry,new_password_entry, confirm_password_entry, main_password_file, salt):
    current_password = current_password_entry.get()

    new_password = new_password_entry.get()
    confirm_password = confirm_password_entry.get()

    current_password_hash = generate_key(current_password, salt)
    
    _, encry_stored_main_password_hash = load_data(main_password_file)

    stored_main_password_hash = decrypt_encrypted_word(encry_stored_main_password_hash, pattern="453607").encode()

    if current_password_hash != stored_main_password_hash:
        output_label.config(text="Incorrect current password.")
        current_password_entry.delete(0, tk.END)
        confirm_password_entry.delete(0, tk.END)
        new_password_entry.delete(0, tk.END)
        output_label.after(3000, lambda: output_label.config(text=""))
        

    elif new_password != confirm_password:
        output_label.config(text="New password and confirm password do not match.")
        output_label.after(3000, lambda: output_label.config(text=""))
    else:
        new_password_hash = generate_key(new_password, salt)
        encry_new_password_hash = generate_encrypted_word(new_password_hash.decode(), pattern="453607")

        save_data((salt, encry_new_password_hash), main_password_file)
        output_label.config(text="Main password changed successfully. Closing application in 5 sec to apply changes.")
        update_data_with_new_key(data_file, current_password_hash, new_password_hash)

        window.after(5000, window.destroy)

def display_change_password(data_file, stored_main_password_hash, output_label, main_password_file, salt):
    def validate_fields():
        current_password = current_password_entry.get()
        new_password = new_password_entry.get()
        confirm_password = confirm_password_entry.get()

        if not current_password or not new_password or not confirm_password:
            messagebox.showwarning("Missing Fields", "Please fill in all fields.")
            return False

        return True
    
    clear_window()

    change_password_frame = ttk.Frame(window, padding="20 30 20 30")
    change_password_frame.pack(expand=True)

    current_password_label = ttk.Label(change_password_frame, text="Current Password:")
    current_password_label.pack()

    current_password_entry = ttk.Entry(change_password_frame, show="*")
    current_password_entry.pack(pady=(0, 10))

    new_password_label = ttk.Label(change_password_frame, text="New Password:")
    new_password_label.pack()

    new_password_entry = ttk.Entry(change_password_frame, show="*")
    new_password_entry.pack(pady=(0, 10))

    confirm_password_label = ttk.Label(change_password_frame, text="Confirm Password:")
    confirm_password_label.pack()

    confirm_password_entry = ttk.Entry(change_password_frame, show="*")
    confirm_password_entry.pack(pady=(0, 10))

    output_label = ttk.Label(change_password_frame, text="")
    output_label.pack(pady=(10, 0))

    button_frame = ttk.Frame(change_password_frame)
    button_frame.pack(pady=(10, 0))

    change_password_button = ttk.Button(button_frame, text="Change Password",command=lambda: change_main_password(data_file, stored_main_password_hash,output_label, current_password_entry,new_password_entry, confirm_password_entry,main_password_file, salt) if validate_fields() else None )
    change_password_button.pack(side=tk.LEFT, padx=(0, 10))

    back_button = ttk.Button(button_frame, text="Back",
                             command=lambda: display_main_menu(data_file, stored_main_password_hash, main_password_file,
                                                              salt))
    back_button.pack(side=tk.LEFT)

    current_password_entry.focus_set()



def edit_saved_password_menu(data_file, stored_main_password_hash, output_label, saved_passwords, *args):
    clear_window()

    def save_changes(selected_item, website_entry, username_entry, password_entry, data_file, stored_main_password_hash, output_label):

        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        save_password(website_entry, username_entry, password_entry, data_file, stored_main_password_hash, output_label)

        encrypted_password_data = str(load_data(data_file))
        saved_data = encrypted_password_data.split(",")

        updated_data = []

        for index, x in enumerate(saved_data):
            if index == selected_item:
                continue
            updated_data.append(x)

        updated_data_str = ",".join(updated_data)
        if updated_data_str[0] == ",":
            updated_data_str = updated_data_str[1:]
        save_data(updated_data_str, data_file)


    def edit_saved_password():
        selected_items = name_listbox.curselection()
        if not selected_items:
            messagebox.showinfo("Error", "No password selected.")
            return

        selected_item = selected_items[0]
        encrypted_password_data = str(load_data(data_file))
        saved_data = encrypted_password_data.split(",")

        if selected_item >= len(saved_data):
            messagebox.showinfo("Error", "Selected index is out of range.")
            return

        selected_entry = saved_data[selected_item]
        name, encrypted_data = selected_entry.split("@")
        decrypted_data = decrypt_data(encrypted_data.encode(), stored_main_password_hash)
        if decrypted_data:
            data_parts = decrypted_data.split(",")
            if len(data_parts) == 2:
                username, password = data_parts
            else:
                messagebox.showinfo("Error", "Invalid data format.")
                return
        else:
            messagebox.showinfo("Error", "Failed to decrypt data.")
            return

        clear_window()

        label_main = tk.Label(window, text="Edit credential", font=(18))
        label_main.pack(pady=40)

        main_fram = tk.Frame(master=window)
        main_fram.pack()

        website_label = tk.Label(main_fram, text="Website:", font=(10))
        website_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky=tk.E)
        website_entry = tk.Entry(main_fram, width=30)
        website_entry.insert(0, name)
        website_entry.grid(row=0, column=1, padx=10, pady=(10, 5), sticky=tk.W)

        username_label = tk.Label(main_fram, text="Username:", font=(10))
        username_label.grid(row=1, column=0, padx=10, pady=(0, 5), sticky=tk.E)
        username_entry = tk.Entry(main_fram, width=30)
        username_entry.insert(0, username)
        username_entry.grid(row=1, column=1, padx=10, pady=(0, 5), sticky=tk.W)

        password_label = tk.Label(main_fram, text="Password:", font=(10))
        password_label.grid(row=2, column=0, padx=10, pady=(0, 5), sticky=tk.E)
        password_entry = tk.Entry(main_fram, width=30)
        password_entry.insert(0, password)
        password_entry.grid(row=2, column=1, padx=10, pady=(0, 5), sticky=tk.W)

        button_frame = tk.Frame(main_fram)
        button_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=30)

        save_button = tk.Button(
            button_frame,
            text="Save",
            width=10,
            command=lambda: save_changes(selected_item, website_entry, username_entry, password_entry, data_file, stored_main_password_hash, output_label)
        )
        save_button.grid(row=0, column=0, padx=5)

        back_button = ttk.Button(
            button_frame,
            text="Go Back",
            width=10,
            command=lambda: edit_saved_password_menu(data_file, stored_main_password_hash, output_label, saved_passwords)
        )
        back_button.grid(row=0, column=1, padx=5)        # Create and pack the "Save" button


    tab_control = ttk.Notebook(window)
    tab_control.pack(fill="both", expand=True)

    tab_delete = ttk.Frame(tab_control)
    tab_control.add(tab_delete, text="Edit Credentials")

    edit_password_frame = ttk.Frame(tab_delete)
    edit_password_frame.pack(padx=20, pady=20)

    name_label = ttk.Label(edit_password_frame, text="Select Credential:")
    name_label.pack()

    # Create the name listbox
    name_listbox = tk.Listbox(edit_password_frame, width=50)
    name_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(edit_password_frame, orient=tk.VERTICAL, command=name_listbox.yview)
    scrollbar.pack(side=tk.LEFT, fill=tk.Y)

    name_listbox.configure(yscrollcommand=scrollbar.set)

    display_website_name(data_file, name_listbox)

    button_frame = ttk.Frame(tab_control)
    button_frame.pack(side=tk.BOTTOM, pady=(10, 50))

    edit_button = ttk.Button(button_frame, text="Edit", command=edit_saved_password)
    edit_button.pack(side=tk.LEFT, padx=(0, 10))

    back_button = ttk.Button(button_frame, text="Back", command=lambda: display_main_menu(data_file, stored_main_password_hash, main_password_file, salt))
    back_button.pack(side=tk.LEFT)

    name_listbox.focus_set()


def display_website_name(data_file, name_listbox):
    encrypted_password_data = str(load_data(data_file))
    saved_data = encrypted_password_data.split(",")

    name_listbox.delete(0, tk.END)

    for data in saved_data:
        name = data.split("@")[0]
        name_listbox.insert(tk.END, name)


def delete_saved_credentials(data_file, stored_main_password_hash, output_label, main_password_file, salt):
    def confirm_deletion(data_file, stored_main_password_hash, output_label, main_password_file, salt, name_listbox):
        selected_indices = name_listbox.curselection()

        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select a website to delete.")
            return

        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete the selected website(s)?")

        if not confirm:
            return

        encrypted_password_data = str(load_data(data_file))
        saved_data = encrypted_password_data.split(",")

        deleted_websites = []

        for index in selected_indices:
            selected_website = name_listbox.get(index)
            deleted = False

            for entry in saved_data:
                if selected_website in entry:
                    saved_data.remove(entry)
                    deleted = True

            if deleted:
                deleted_websites.append(selected_website)

        if not deleted_websites:
            messagebox.showwarning("Deletion Error", "Cannot find the selected website(s) in saved credentials.")
            return

        updated_data_str = ",".join(saved_data)
        save_data(updated_data_str, data_file)

        deleted_websites_str = "\n- ".join(deleted_websites)
        messagebox.showinfo("Deletion Successful", f"The website(s) have been deleted:\n- {deleted_websites_str}")

        # Clear the listbox and reload website names
        name_listbox.delete(0, tk.END)
        display_website_name(data_file, name_listbox)
    clear_window()
    tab_control = ttk.Notebook(window)
    tab_control.pack(fill="both", expand=True)

    tab_delete = ttk.Frame(tab_control)
    tab_control.add(tab_delete, text="Delete Credentials")

    delete_credentials_frame = ttk.Frame(tab_delete)
    delete_credentials_frame.pack(padx=20, pady=20)

    name_label = ttk.Label(delete_credentials_frame, text="Select Credential:")
    name_label.pack()

    # Create the name listbox
    name_listbox = tk.Listbox(delete_credentials_frame, width=50)
    name_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(delete_credentials_frame, orient=tk.VERTICAL, command=name_listbox.yview)
    scrollbar.pack(side=tk.LEFT, fill=tk.Y)

    name_listbox.configure(yscrollcommand=scrollbar.set)

    display_website_name(data_file, name_listbox)

    button_frame = ttk.Frame(tab_control)
    button_frame.pack(side=tk.BOTTOM, pady=(10, 50))

    delete_button = ttk.Button(button_frame, text="Delete", command=lambda: confirm_deletion(data_file, stored_main_password_hash, output_label, main_password_file, salt, name_listbox))
    delete_button.pack(side=tk.LEFT, padx=(0, 10))

    back_button = ttk.Button(button_frame, text="Back", command=lambda: display_main_menu(data_file, stored_main_password_hash, main_password_file, salt))
    back_button.pack(side=tk.LEFT)

    name_listbox.focus_set()


def encrypt_files_in_directory(data_file, stored_main_password_hash, output_label, main_password_file, salt):
    directory = 'data/files'

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
            # print(f'Encrypted file: {file_path}')

    messagebox.showinfo('success','Encryption completed successfully.')

def decrypt_file(file_path, stored_main_password_hash):

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = decrypt_data(encrypted_data, stored_main_password_hash)

    decrypted_file_path = file_path[:-10]  # Remove the '.encrypted' extension
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    os.remove(file_path)
    # messagebox.showinfo("Decrypted success",f'file "{decrypted_file_path}" is decrypted successfuly')

def list_files_in_directory(directory, file_name_listbox):
    file_name_listbox.delete(0, tk.END)
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) and filename.endswith('.encrypted'):
            file_name_listbox.insert(tk.END, filename)

def decrypt_files_in_directory(data_file, stored_main_password_hash, output_label, main_password_file, salt):
    clear_window()

    directory = "data/files"

    tab_control = ttk.Notebook(window)
    tab_control.pack(fill="both", expand=True)

    tab_delete = ttk.Frame(tab_control)
    tab_control.add(tab_delete, text="Decrypt File")

    file_decrypt_frame = ttk.Frame(tab_delete)
    file_decrypt_frame.pack(padx=20, pady=20)

    name_label = ttk.Label(file_decrypt_frame, text="Select File:")
    name_label.pack()

    select_all_var = tk.IntVar()
    select_all_checkbox = ttk.Checkbutton(file_decrypt_frame, text="Select All",
                                          variable=select_all_var, command=lambda: select_all_files(file_name_listbox, select_all_var.get()))
    select_all_checkbox.pack()

    file_name_listbox = tk.Listbox(file_decrypt_frame, width=50, selectmode=tk.MULTIPLE)
    file_name_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(file_decrypt_frame, orient=tk.VERTICAL, command=file_name_listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    file_name_listbox.configure(yscrollcommand=scrollbar.set)

    list_files_in_directory(directory, file_name_listbox)

    button_frame = ttk.Frame(tab_delete)
    button_frame.pack(side=tk.BOTTOM, pady=(10, 50))

    decrypt_button = tk.Button(button_frame, text="Decrypt",
                               command=lambda: decrypt_selected_files(directory, file_name_listbox.curselection(),
                                                                      stored_main_password_hash, file_name_listbox))
    decrypt_button.pack(side=tk.LEFT, padx=5)

    go_back_button = tk.Button(button_frame, text="Go Back",
                               command=lambda: display_main_menu(data_file, stored_main_password_hash, main_password_file, salt))
    go_back_button.pack(side=tk.LEFT, padx=5)

    file_name_listbox.focus_set()


def select_all_files(file_name_listbox, select):
    file_name_listbox.select_clear(0, tk.END)
    if select:
        file_name_listbox.select_set(0, tk.END)


def decrypt_selected_files(directory, selected_indices, stored_main_password_hash, file_name_listbox):
    num_files_decrypted = 0

    for index in selected_indices:
        file_name = file_name_listbox.get(index)
        file_path = os.path.join(directory, file_name)
        decrypt_file(file_path, stored_main_password_hash)
        num_files_decrypted += 1

    messagebox.showinfo("Decryption Status", f"{num_files_decrypted} file(s) decrypted successfully.")
    list_files_in_directory(directory, file_name_listbox)

pattern = "453607"
salt = os.urandom(16)
main_password_file = 'data\main_password.pickle'
data_file = 'data\password_data.pickle'

# window
window = ttk.Window(themename="flatly")
window.title("Secret Keeper")
window.iconbitmap(resource_path("icon.ico"))
window.geometry("450x500")
window.resizable(False, False)  # Fix window size

# Center the window on the screen
window.update_idletasks()
width = window.winfo_width()
height = window.winfo_height()
x = (window.winfo_screenwidth() // 2) - (width // 2)
y = (window.winfo_screenheight() // 2) - (height // 2)
window.geometry(f"{width}x{height}+{x}+{y}")

output_var = ttk.StringVar()
password_var = ttk.StringVar()
label1_var = ttk.StringVar()
label1 = ttk.Label(master=window, text="Enter main password", font=("Helvetica", 14), textvariable=label1_var)
label1.pack(pady=(150,10))

set_label1_text(main_password_file)

input_frame = ttk.Frame(master=window)

entry_field = ttk.Entry(master=input_frame, textvariable=password_var, font=("Helvetica", 12), show="*", width=20)
entry_field.pack(side=tk.LEFT, padx=5, pady=5)
entry_field.bind('<Return>', lambda event: main_password_checker(main_password_file, out_label, pattern)if is_main_password_exist() else setup_main_password(main_password_file, salt, pattern=pattern))

button = ttk.Button(master=input_frame, text="Enter",
                    command=lambda: main_password_checker(main_password_file, output_label=out_label, pattern = pattern) if is_main_password_exist()
                    else setup_main_password(main_password_file, salt, pattern), width=10)
button.pack(side=tk.LEFT, padx=5, pady=5)

out_label = ttk.Label(master=window, text="Output", textvariable=output_var, font=("Helvetica", 12))

input_frame.pack()
out_label.pack(pady=20)


style = ttk.Style()
style.configure("IconButton.TButton", background="white", relief="flat")

window.mainloop()

#21254A, 8240BF, 6043D2


# border: none;
# outline: none;
# padding: 5px;
# border-bottom: 1px solid #698361


# padding: 8px;
# background-color:  #2A562C;
# color: #ffffff;
# font-size:18px;
# border: none;


# color: rgb(105, 131, 97);
# font: 58pt "Weddingday Personal Use";

# color: rgb(105, 131, 97);
# font: 38pt "Weddingday Personal Use";


# background-color: rgb(244, 231, 215);


# QPushButton {
#     padding: 8px;
#     background-color: #2A562C;
#     color: #ffffff;
#     font-size: 18px;
#     border: none;
# }

# QPushButton:hover {
#     background-color: rgb(105, 131, 97)
# }

# QPushButton:pressed {
#     background-color: #000000;
#     color: #ffffff;
# }
