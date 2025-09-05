import customtkinter
from tkinter import messagebox
import clipboard
from PIL import Image
from utils import (resource_path, generate_password, save_data, load_data, encrypt_data, decrypt_data,
                   encrypt_files_in_directory, list_files_in_directory, decrypt_selected_files, decrypt_encrypted_word,
                   generate_key, generate_encrypted_word)
import os

class PasswordManagerUI(customtkinter.CTk):
    def __init__(self, data_file, main_password_file, salt, pattern):
        super().__init__()
        self.data_file = data_file
        self.main_password_file = main_password_file
        self.salt = salt
        self.pattern = pattern
        self.stored_main_password_hash = None

        self.title("Secret Keeper")
        self.geometry("450x500")
        self.resizable(False, False)

        self.create_login_widgets()

    def create_login_widgets(self):
        self.clear_window()

        self.login_frame = customtkinter.CTkFrame(self)
        self.login_frame.pack(pady=150, padx=20, fill="both", expand=True)

        self.label1_var = customtkinter.StringVar()
        self.label1 = customtkinter.CTkLabel(self.login_frame, textvariable=self.label1_var, font=("Helvetica", 14))
        self.label1.pack(pady=10)

        self.password_var = customtkinter.StringVar()
        self.entry_field = customtkinter.CTkEntry(self.login_frame, textvariable=self.password_var, font=("Helvetica", 12), show="*", width=200)
        self.entry_field.pack(pady=5)
        self.entry_field.bind('<Return>', self.login_or_setup)

        self.button = customtkinter.CTkButton(self.login_frame, text="Enter", command=self.login_or_setup, width=100)
        self.button.pack(pady=5)

        self.output_var = customtkinter.StringVar()
        self.out_label = customtkinter.CTkLabel(self.login_frame, textvariable=self.output_var, font=("Helvetica", 12))
        self.out_label.pack(pady=20)

        self.set_label1_text()

    def set_label1_text(self):
        if not os.path.exists(self.main_password_file):
            self.label1_var.set("Create a main password:")
        else:
            self.label1_var.set("Enter main password")

    def login_or_setup(self, event=None):
        if not os.path.exists(self.main_password_file):
            self.setup_main_password()
        else:
            self.main_password_checker()

    def setup_main_password(self):
        main_password = self.password_var.get()
        main_password_hash = generate_key(main_password, self.salt)
        encry_main_password_hash = generate_encrypted_word(main_password_hash.decode(), pattern=self.pattern)
        save_data((self.salt, encry_main_password_hash), self.main_password_file)
        messagebox.showinfo("Success", "Password saved successfully.")
        self.password_var.set("")
        self.set_label1_text()

    def main_password_checker(self):
        try:
            salt, encry_stored_main_password_hash = load_data(self.main_password_file)
            stored_main_password_hash = decrypt_encrypted_word(encry_stored_main_password_hash, pattern=self.pattern).encode()

            main_password = self.password_var.get()
            main_password_hash = generate_key(main_password, salt)

            if main_password_hash == stored_main_password_hash:
                self.output_var.set("Logging successful")
                self.stored_main_password_hash = stored_main_password_hash
                self.display_main_menu()
            else:
                self.output_var.set("Incorrect password")
                self.after(2000, lambda: self.output_var.set(""))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def display_main_menu(self):
        self.clear_window()

        menu_frame = customtkinter.CTkFrame(self)
        menu_frame.pack(pady=30, padx=20, fill="both", expand=True)

        menu_label = customtkinter.CTkLabel(menu_frame, text="Menu", font=("Helvetica", 14))
        menu_label.pack(pady=10)

        options = [
            ("Create new credential", self.generate_password_menu),
            ("Display saved passwords", self.load_password),
            ("Edit saved password", self.edit_saved_password_menu),
            ("Delete saved password", self.delete_saved_credentials),
            ("Change main password", self.display_change_password),
            ("Encrypt file", self.encrypt_files_menu),
            ("Decrypt file", self.decrypt_files_menu)
        ]

        for option_text, option_command in options:
            button = customtkinter.CTkButton(menu_frame, text=option_text, width=200, command=option_command)
            button.pack(pady=5)

    def clear_window(self):
        for child in self.winfo_children():
            child.destroy()

    def generate_password_menu(self):
        self.clear_window()

        label_main = customtkinter.CTkLabel(self, text="Create credential", font=("Helvetica", 18))
        label_main.pack(pady=40)

        main_frame = customtkinter.CTkFrame(self)
        main_frame.pack(padx=20, pady=10, fill="both", expand=True)

        website_label = customtkinter.CTkLabel(main_frame, text="Website:")
        website_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")
        website_entry = customtkinter.CTkEntry(main_frame, width=200)
        website_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        username_label = customtkinter.CTkLabel(main_frame, text="Username:")
        username_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
        username_entry = customtkinter.CTkEntry(main_frame, width=200)
        username_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        password_label = customtkinter.CTkLabel(main_frame, text="Password:")
        password_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
        password_entry = customtkinter.CTkEntry(main_frame, width=200)
        password_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        button_frame = customtkinter.CTkFrame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=30)

        generate_button = customtkinter.CTkButton(button_frame, text="Generate", width=100, command=lambda: generate_password(website_entry, username_entry, password_entry))
        generate_button.grid(row=0, column=0, padx=5)

        save_button = customtkinter.CTkButton(button_frame, text="Save", width=100, command=lambda: self.save_password(website_entry, username_entry, password_entry))
        save_button.grid(row=0, column=1, padx=5)

        back_button = customtkinter.CTkButton(button_frame, text="Go Back", width=100, command=self.display_main_menu)
        back_button.grid(row=0, column=2, padx=5)

    def save_password(self, website_entry, username_entry, password_entry):
        website = website_entry.get().lower()
        username = username_entry.get()
        password = password_entry.get()

        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        encrypted_data = encrypt_data(f"{username},{password}", self.stored_main_password_hash).decode()
        if not os.path.exists(self.data_file):
            save_data(f"{website}@{encrypted_data}", self.data_file)
        else:
            encrypt_password_data = load_data(self.data_file)
            save_data(f"{encrypt_password_data},{website}@{encrypted_data}", self.data_file)

        messagebox.showinfo("Success", "Changes have been saved successfully!")
        website_entry.delete(0, 'end')
        username_entry.delete(0, 'end')
        password_entry.delete(0, 'end')

    def load_password(self):
        self.clear_window()

        try:
            encrypted_password_data = str(load_data(self.data_file))
            saved_data = encrypted_password_data.split(",")
        except FileNotFoundError:
            saved_data = []

        save_menu_frame = customtkinter.CTkFrame(self)
        save_menu_frame.pack(pady=20, padx=20, fill="both", expand=True)

        label = customtkinter.CTkLabel(save_menu_frame, text="Available credentials", font=("Helvetica", 18))
        label.pack(pady=20)

        scrollable_frame = customtkinter.CTkScrollableFrame(save_menu_frame)
        scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)

        for x in saved_data:
            data = x.split("@")
            if len(data) >= 2:
                button = customtkinter.CTkButton(scrollable_frame, text=data[0].capitalize(), command=lambda website=data[0], websites=saved_data: self.display_credentials(website, websites))
                button.pack(fill="x", pady=5)

        back_button = customtkinter.CTkButton(save_menu_frame, text="Go Back", command=self.display_main_menu)
        back_button.pack(pady=20)

    def display_credentials(self, website, websites):
        self.clear_window()

        website_data = None
        for x in websites:
            data = x.split('@')
            if len(data) >= 2 and data[0].lower() == website.lower():
                website_data = data[1]
                break

        if website_data:
            decrypted_data = decrypt_data(website_data.encode(), self.stored_main_password_hash)
            if decrypted_data:
                username, password = decrypted_data.split(",")

                label = customtkinter.CTkLabel(self, text=str(website).capitalize(), font=("Helvetica", 24))
                label.pack(pady=50)

                username_frame = customtkinter.CTkFrame(self)
                username_frame.pack(pady=5)
                username_label = customtkinter.CTkLabel(username_frame, text="Username: " + username)
                username_label.pack(side="left", padx=10)
                copy_username_button = customtkinter.CTkButton(username_frame, text="Copy", command=lambda: clipboard.copy(username), width=50)
                copy_username_button.pack(side="left")

                password_frame = customtkinter.CTkFrame(self)
                password_frame.pack(pady=5)
                password_label = customtkinter.CTkLabel(password_frame, text="Password: " + password)
                password_label.pack(side="left", padx=10)
                copy_password_button = customtkinter.CTkButton(password_frame, text="Copy", command=lambda: clipboard.copy(password), width=50)
                copy_password_button.pack(side="left")

                back_button = customtkinter.CTkButton(self, text="Go Back", command=self.load_password)
                back_button.pack(pady=20)
            else:
                messagebox.showerror("Error", "Invalid key. Please close the program and retry.")
        else:
            messagebox.showerror("Error", f"Sorry, credentials for {website} not found.")

    def edit_saved_password_menu(self):
        self.clear_window()

        try:
            encrypted_password_data = str(load_data(self.data_file))
            saved_data = encrypted_password_data.split(",")
        except FileNotFoundError:
            saved_data = []

        edit_menu_frame = customtkinter.CTkFrame(self)
        edit_menu_frame.pack(pady=20, padx=20, fill="both", expand=True)

        label = customtkinter.CTkLabel(edit_menu_frame, text="Edit credentials", font=("Helvetica", 18))
        label.pack(pady=20)

        scrollable_frame = customtkinter.CTkScrollableFrame(edit_menu_frame)
        scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)

        for index, x in enumerate(saved_data):
            data = x.split("@")
            if len(data) >= 2:
                frame = customtkinter.CTkFrame(scrollable_frame)
                frame.pack(fill="x", pady=2)

                label = customtkinter.CTkLabel(frame, text=data[0].capitalize())
                label.pack(side="left", padx=10)

                edit_button = customtkinter.CTkButton(frame, text="Edit", width=50, command=lambda i=index, d=data: self.edit_credential(i, d))
                edit_button.pack(side="right", padx=10)

        back_button = customtkinter.CTkButton(edit_menu_frame, text="Go Back", command=self.display_main_menu)
        back_button.pack(pady=20)

    def edit_credential(self, index, data):
        self.clear_window()
        name, encrypted_data = data
        decrypted_data = decrypt_data(encrypted_data.encode(), self.stored_main_password_hash)
        username, password = decrypted_data.split(',')

        label_main = customtkinter.CTkLabel(self, text="Edit credential", font=("Helvetica", 18))
        label_main.pack(pady=40)

        main_frame = customtkinter.CTkFrame(self)
        main_frame.pack(padx=20, pady=10, fill="both", expand=True)

        website_label = customtkinter.CTkLabel(main_frame, text="Website:")
        website_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")
        website_entry = customtkinter.CTkEntry(main_frame, width=200)
        website_entry.insert(0, name)
        website_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        username_label = customtkinter.CTkLabel(main_frame, text="Username:")
        username_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
        username_entry = customtkinter.CTkEntry(main_frame, width=200)
        username_entry.insert(0, username)
        username_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        password_label = customtkinter.CTkLabel(main_frame, text="Password:")
        password_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
        password_entry = customtkinter.CTkEntry(main_frame, width=200)
        password_entry.insert(0, password)
        password_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        button_frame = customtkinter.CTkFrame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=30)

        save_button = customtkinter.CTkButton(button_frame, text="Save", width=100, command=lambda: self.save_edited_password(index, website_entry, username_entry, password_entry))
        save_button.grid(row=0, column=0, padx=5)

        back_button = customtkinter.CTkButton(button_frame, text="Go Back", width=100, command=self.edit_saved_password_menu)
        back_button.grid(row=0, column=1, padx=5)

    def save_edited_password(self, index, website_entry, username_entry, password_entry):
        website = website_entry.get().lower()
        username = username_entry.get()
        password = password_entry.get()

        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        encrypted_password_data = str(load_data(self.data_file))
        saved_data = encrypted_password_data.split(",")

        encrypted_data = encrypt_data(f"{username},{password}", self.stored_main_password_hash).decode()
        saved_data[index] = f"{website}@{encrypted_data}"

        save_data(",".join(saved_data), self.data_file)
        messagebox.showinfo("Success", "Changes have been saved successfully!")
        self.edit_saved_password_menu()

    def delete_saved_credentials(self):
        self.clear_window()

        try:
            encrypted_password_data = str(load_data(self.data_file))
            saved_data = encrypted_password_data.split(",")
        except FileNotFoundError:
            saved_data = []

        delete_menu_frame = customtkinter.CTkFrame(self)
        delete_menu_frame.pack(pady=20, padx=20, fill="both", expand=True)

        label = customtkinter.CTkLabel(delete_menu_frame, text="Delete credentials", font=("Helvetica", 18))
        label.pack(pady=20)

        self.selected_to_delete = []

        def on_checkbox_changed(var, name):
            if var.get():
                self.selected_to_delete.append(name)
            else:
                self.selected_to_delete.remove(name)

        scrollable_frame = customtkinter.CTkScrollableFrame(delete_menu_frame)
        scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)

        for x in saved_data:
            name = x.split("@")[0]
            var = customtkinter.BooleanVar()
            checkbox = customtkinter.CTkCheckBox(scrollable_frame, text=name.capitalize(), variable=var, command=lambda v=var, n=name: on_checkbox_changed(v, n))
            checkbox.pack(fill="x", pady=2)

        button_frame = customtkinter.CTkFrame(delete_menu_frame)
        button_frame.pack(pady=20)

        delete_button = customtkinter.CTkButton(button_frame, text="Delete", width=100, command=self.confirm_deletion)
        delete_button.pack(side="left", padx=10)

        back_button = customtkinter.CTkButton(button_frame, text="Go Back", width=100, command=self.display_main_menu)
        back_button.pack(side="left", padx=10)

    def confirm_deletion(self):
        if not self.selected_to_delete:
            messagebox.showwarning("No Selection", "Please select a website to delete.")
            return

        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete the selected website(s)?")

        if not confirm:
            return

        encrypted_password_data = str(load_data(self.data_file))
        saved_data = encrypted_password_data.split(",")

        updated_data = [x for x in saved_data if x.split("@")[0] not in self.selected_to_delete]

        save_data(",".join(updated_data), self.data_file)

        messagebox.showinfo("Deletion Successful", f"The website(s) have been deleted.")
        self.delete_saved_credentials()

    def display_change_password(self):
        self.clear_window()
        change_password_frame = customtkinter.CTkFrame(self, corner_radius=10)
        change_password_frame.pack(padx=20, pady=30, fill="both", expand=True)

        title_label = customtkinter.CTkLabel(change_password_frame, text="Change Main Password", font=("Helvetica", 18, "bold"))
        title_label.pack(pady=20)

        current_password_label = customtkinter.CTkLabel(change_password_frame, text="Current Password:")
        current_password_label.pack(pady=(10,0))
        current_password_entry = customtkinter.CTkEntry(change_password_frame, show="*", width=250)
        current_password_entry.pack()

        new_password_label = customtkinter.CTkLabel(change_password_frame, text="New Password:")
        new_password_label.pack(pady=(10,0))
        new_password_entry = customtkinter.CTkEntry(change_password_frame, show="*", width=250)
        new_password_entry.pack()

        confirm_password_label = customtkinter.CTkLabel(change_password_frame, text="Confirm Password:")
        confirm_password_label.pack(pady=(10,0))
        confirm_password_entry = customtkinter.CTkEntry(change_password_frame, show="*", width=250)
        confirm_password_entry.pack()

        output_label = customtkinter.CTkLabel(change_password_frame, text="", font=("Helvetica", 12))
        output_label.pack(pady=20)

        button_frame = customtkinter.CTkFrame(change_password_frame)
        button_frame.pack(pady=20)

        change_password_button = customtkinter.CTkButton(button_frame, text="Change Password", command=lambda: self.change_main_password(current_password_entry, new_password_entry, confirm_password_entry, output_label))
        change_password_button.pack(side="left", padx=10)

        back_button = customtkinter.CTkButton(button_frame, text="Back", command=self.display_main_menu)
        back_button.pack(side="left", padx=10)

    def change_main_password(self, current_password_entry, new_password_entry, confirm_password_entry, output_label):
        current_password = current_password_entry.get()
        new_password = new_password_entry.get()
        confirm_password = confirm_password_entry.get()

        current_password_hash = generate_key(current_password, self.salt)

        if current_password_hash != self.stored_main_password_hash:
            output_label.configure(text="Incorrect current password.")
        elif new_password != confirm_password:
            output_label.configure(text="New password and confirm password do not match.")
        else:
            new_password_hash = generate_key(new_password, self.salt)
            encry_new_password_hash = generate_encrypted_word(new_password_hash.decode(), pattern=self.pattern)

            save_data((self.salt, encry_new_password_hash), self.main_password_file)
            self.update_data_with_new_key(current_password_hash, new_password_hash)
            output_label.configure(text="Main password changed successfully. Restarting to apply changes.")
            self.after(3000, self.destroy)

    def update_data_with_new_key(self, old_key, new_key):
        if os.path.exists(self.data_file):
            encrypted_password_data = str(load_data(self.data_file))
            saved_data = encrypted_password_data.split(",")

            new_encrypted_data = []

            for data in saved_data:
                credential = data.split("@")
                decrypted_data = str(decrypt_data(credential[1].encode(), old_key))
                new_encrypted_data.append(f"{credential[0]}@{encrypt_data(decrypted_data, new_key).decode()}")

            save_data(",".join(new_encrypted_data), self.data_file)

        directory = "data/files"

        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path) and filename.endswith('.encrypted'):
                with open(file_path, "rb") as file:
                    encrypt_file_data = file.read()

                decrypted_data = decrypt_data(encrypt_file_data, old_key)
                new_encrypt_data = encrypt_data(decrypted_data, new_key)

                with open(file_path, 'wb') as file:
                    file.write(new_encrypt_data)

    def encrypt_files_menu(self):
        directory = 'data/files'
        encrypt_files_in_directory(directory, self.stored_main_password_hash)

    def decrypt_files_menu(self):
        self.clear_window()
        directory = "data/files"

        decrypt_frame = customtkinter.CTkFrame(self)
        decrypt_frame.pack(pady=20, padx=20, fill="both", expand=True)

        label = customtkinter.CTkLabel(decrypt_frame, text="Decrypt Files", font=("Helvetica", 18))
        label.pack(pady=20)

        file_listbox = customtkinter.CTkTextbox(decrypt_frame, width=350, height=200)
        file_listbox.pack(pady=10)

        self.selected_files_to_decrypt = []

        def on_checkbox_changed(var, name):
            if var.get():
                self.selected_files_to_decrypt.append(name)
            else:
                self.selected_files_to_decrypt.remove(name)

        scrollable_frame = customtkinter.CTkScrollableFrame(decrypt_frame)
        scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)

        for filename in os.listdir(directory):
            if os.path.isfile(os.path.join(directory, filename)) and filename.endswith('.encrypted'):
                var = customtkinter.BooleanVar()
                checkbox = customtkinter.CTkCheckBox(scrollable_frame, text=filename, variable=var, command=lambda v=var, n=filename: on_checkbox_changed(v,n))
                checkbox.pack(fill="x", pady=2)

        button_frame = customtkinter.CTkFrame(decrypt_frame)
        button_frame.pack(pady=20)

        decrypt_button = customtkinter.CTkButton(button_frame, text="Decrypt", command=lambda: self.decrypt_selected(directory))
        decrypt_button.pack(side="left", padx=10)

        back_button = customtkinter.CTkButton(button_frame, text="Back", command=self.display_main_menu)
        back_button.pack(side="left", padx=10)

    def decrypt_selected(self, directory):
        if not self.selected_files_to_decrypt:
            messagebox.showwarning("No Selection", "Please select files to decrypt.")
            return

        for file_name in self.selected_files_to_decrypt:
            file_path = os.path.join(directory, file_name)
            decrypt_file(file_path, self.stored_main_password_hash)

        messagebox.showinfo("Success", f"{len(self.selected_files_to_decrypt)} file(s) decrypted successfully.")
        self.decrypt_files_menu()
