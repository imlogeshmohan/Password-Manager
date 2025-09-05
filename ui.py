import customtkinter
from tkinter import messagebox, filedialog
import clipboard
import csv
import json
from PIL import Image
from utils import (resource_path, generate_random_password, save_data, load_data, encrypt_data, decrypt_data,
                   decrypt_encrypted_word, generate_key, generate_encrypted_word)
import os

class PasswordManagerUI(customtkinter.CTk):
    def __init__(self, data_file, main_password_file, salt, pattern):
        super().__init__()
        self.data_file = data_file
        self.main_password_file = main_password_file
        self.salt = salt
        self.pattern = pattern
        self.stored_main_password_hash = None
        self.vaults = ["Default"]

        self.title("Neox Password")
        self.geometry("1024x768")
        self.configure(fg_color="#CFC2E8")

        customtkinter.set_appearance_mode("Dark")

        self.create_login_widgets()

    def create_login_widgets(self):
        self.clear_window()

        self.login_frame = customtkinter.CTkFrame(self, fg_color="#141418", corner_radius=20)
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")

        title = customtkinter.CTkLabel(self.login_frame, text="Neox Password", font=("Poppins", 24, "bold"))
        title.pack(pady=(40, 20), padx=100)

        self.label1_var = customtkinter.StringVar()
        self.label1 = customtkinter.CTkLabel(self.login_frame, textvariable=self.label1_var, font=("Poppins", 14))
        self.label1.pack(pady=10)

        self.password_var = customtkinter.StringVar()
        self.entry_field = customtkinter.CTkEntry(self.login_frame, textvariable=self.password_var, font=("Poppins", 12), show="*", width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        self.entry_field.pack(pady=5, padx=40)
        self.entry_field.bind('<Return>', self.login_or_setup)

        self.button = customtkinter.CTkButton(self.login_frame, text="Enter", command=self.login_or_setup, width=100, corner_radius=10, fg_color="#7B6CFF", hover_color="#9B8CFF")
        self.button.pack(pady=20)

        self.output_var = customtkinter.StringVar()
        self.out_label = customtkinter.CTkLabel(self.login_frame, textvariable=self.output_var, font=("Poppins", 12))
        self.out_label.pack(pady=(0,40))

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
            self.salt = salt
            stored_main_password_hash = decrypt_encrypted_word(encry_stored_main_password_hash, pattern=self.pattern).encode()

            main_password = self.password_var.get()
            main_password_hash = generate_key(main_password, salt)

            if main_password_hash == stored_main_password_hash:
                self.output_var.set("Logging successful")
                self.stored_main_password_hash = stored_main_password_hash
                self.create_main_layout()
            else:
                self.output_var.set("Incorrect password")
                self.after(2000, lambda: self.output_var.set(""))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def clear_window(self):
        for child in self.winfo_children():
            child.destroy()

    def create_main_layout(self):
        self.clear_window()

        main_container = customtkinter.CTkFrame(self, fg_color="#141418")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        self.sidebar_frame = customtkinter.CTkFrame(main_container, width=150, fg_color="#181a1f", corner_radius=0)
        self.sidebar_frame.pack(side="left", fill="y")

        self.load_sidebar()

        list_panel_frame = customtkinter.CTkFrame(main_container, fg_color="#141418")
        list_panel_frame.pack(side="left", fill="both", expand=True, pady=10, padx=10)

        top_bar_frame = customtkinter.CTkFrame(list_panel_frame, fg_color="transparent")
        top_bar_frame.pack(fill="x", padx=20, pady=10)

        self.search_bar = customtkinter.CTkEntry(top_bar_frame, placeholder_text="Buscar...", fg_color="#181a1f", border_width=0, corner_radius=10)
        self.search_bar.pack(side="left", fill="x", expand=True, padx=(0,10))
        self.search_bar.bind("<KeyRelease>", self.search_passwords)

        add_password_button = customtkinter.CTkButton(top_bar_frame, text="+", width=30, corner_radius=10, fg_color="#7B6CFF", hover_color="#9B8CFF", command=self.add_password_window)
        add_password_button.pack(side="left")

        self.favorites_list_frame = customtkinter.CTkFrame(list_panel_frame, fg_color="transparent")
        self.favorites_list_frame.pack(fill="both", expand=True, padx=20, pady=10)
        self.favorites_list = customtkinter.CTkScrollableFrame(self.favorites_list_frame, fg_color="transparent")
        self.favorites_list.pack(fill="both", expand=True)

        self.detail_panel_frame = customtkinter.CTkFrame(main_container, width=300, fg_color="#181a1f", corner_radius=0)
        self.detail_panel_frame.pack(side="right", fill="y")

        self.load_passwords_into_ui()

    def load_sidebar(self):
        for widget in self.sidebar_frame.winfo_children():
            widget.destroy()

        all_button = customtkinter.CTkButton(self.sidebar_frame, text="All", fg_color="transparent", command=lambda: self.load_passwords_into_ui())
        all_button.pack(pady=10, padx=10)

        vaults_label = customtkinter.CTkLabel(self.sidebar_frame, text="Vaults", font=("Poppins", 16, "bold"))
        vaults_label.pack(pady=10)

        for vault in self.vaults:
            vault_button = customtkinter.CTkButton(self.sidebar_frame, text=vault, fg_color="transparent", command=lambda v=vault: self.filter_by_vault(v))
            vault_button.pack(pady=5, padx=10)

        manage_vaults_button = customtkinter.CTkButton(self.sidebar_frame, text="Manage Vaults", command=self.manage_vaults_window)
        manage_vaults_button.pack(pady=10)


        import_button = customtkinter.CTkButton(self.sidebar_frame, text="Import", command=self.import_passwords, fg_color="#7B6CFF", hover_color="#9B8CFF", corner_radius=10)
        import_button.pack(pady=20, side="bottom")
        export_button = customtkinter.CTkButton(self.sidebar_frame, text="Export", command=self.export_passwords, fg_color="#7B6CFF", hover_color="#9B8CFF", corner_radius=10)
        export_button.pack(pady=10, side="bottom")

    def add_password_window(self):
        add_window = customtkinter.CTkToplevel(self)
        add_window.title("Add New Password")
        add_window.geometry("400x500")
        add_window.transient(self)
        add_window.grab_set()

        main_frame = customtkinter.CTkFrame(add_window, fg_color="#141418")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        website_label = customtkinter.CTkLabel(main_frame, text="Website:")
        website_label.pack(pady=(10,0))
        website_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        website_entry.pack()

        username_label = customtkinter.CTkLabel(main_frame, text="Username:")
        username_label.pack(pady=(10,0))
        username_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        username_entry.pack()

        vault_label = customtkinter.CTkLabel(main_frame, text="Vault:")
        vault_label.pack(pady=(10,0))
        vault_menu = customtkinter.CTkOptionMenu(main_frame, values=self.vaults, width=250, corner_radius=10, fg_color="#181a1f")
        vault_menu.pack()

        category_label = customtkinter.CTkLabel(main_frame, text="Category:")
        category_label.pack(pady=(10,0))
        category_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        category_entry.pack()

        tags_label = customtkinter.CTkLabel(main_frame, text="Tags (comma-separated):")
        tags_label.pack(pady=(10,0))
        tags_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        tags_entry.pack()


        password_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        password_frame.pack(pady=(10,0))
        password_label = customtkinter.CTkLabel(password_frame, text="Password:")
        password_label.pack()
        password_entry = customtkinter.CTkEntry(password_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        password_entry.pack(side="left", padx=(0,5))
        generate_button = customtkinter.CTkButton(password_frame, text="Generate", width=80, corner_radius=10, fg_color="#7B6CFF", hover_color="#9B8CFF",
                                                command=lambda: self.generate_password_window(password_entry))
        generate_button.pack(side="left")

        save_button = customtkinter.CTkButton(main_frame, text="Save", width=100, corner_radius=10, fg_color="#7B6CFF", hover_color="#9B8CFF",
                                            command=lambda: self.save_password(website_entry, username_entry, password_entry, category_entry, tags_entry, vault_menu, add_window))
        save_button.pack(pady=20)


    def save_password(self, website_entry, username_entry, password_entry, category_entry, tags_entry, vault_menu, window):
        website = website_entry.get().lower()
        username = username_entry.get()
        password = password_entry.get()
        category = category_entry.get()
        tags = [tag.strip() for tag in tags_entry.get().split(',')]
        vault = vault_menu.get()

        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.", parent=window)
            return

        new_entry = {"username": username, "password": password, "category": category, "tags": tags, "vault": vault}
        encrypted_entry = encrypt_data(new_entry, self.stored_main_password_hash)

        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        data[website] = encrypted_entry.decode('utf-8')

        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Success", "Password saved successfully!", parent=window)
        self.load_passwords_into_ui()
        self.load_sidebar()
        window.destroy()

    def edit_password_window(self, website, username, password, category, tags, vault):
        edit_window = customtkinter.CTkToplevel(self)
        edit_window.title("Edit Password")
        edit_window.geometry("400x500")
        edit_window.transient(self)
        edit_window.grab_set()

        main_frame = customtkinter.CTkFrame(edit_window, fg_color="#141418")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        website_label = customtkinter.CTkLabel(main_frame, text="Website:")
        website_label.pack(pady=(10,0))
        website_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        website_entry.insert(0, website)
        website_entry.pack()

        username_label = customtkinter.CTkLabel(main_frame, text="Username:")
        username_label.pack(pady=(10,0))
        username_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        username_entry.insert(0, username)
        username_entry.pack()

        vault_label = customtkinter.CTkLabel(main_frame, text="Vault:")
        vault_label.pack(pady=(10,0))
        vault_menu = customtkinter.CTkOptionMenu(main_frame, values=self.vaults, width=250, corner_radius=10, fg_color="#181a1f")
        vault_menu.set(vault)
        vault_menu.pack()

        category_label = customtkinter.CTkLabel(main_frame, text="Category:")
        category_label.pack(pady=(10,0))
        category_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        category_entry.insert(0, category)
        category_entry.pack()

        tags_label = customtkinter.CTkLabel(main_frame, text="Tags (comma-separated):")
        tags_label.pack(pady=(10,0))
        tags_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        tags_entry.insert(0, ", ".join(tags))
        tags_entry.pack()


        password_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        password_frame.pack(pady=(10,0))
        password_label = customtkinter.CTkLabel(password_frame, text="Password:")
        password_label.pack()
        password_entry = customtkinter.CTkEntry(main_frame, width=250, corner_radius=10, fg_color="#181a1f", border_width=0)
        password_entry.insert(0, password)
        password_entry.pack(side="left", padx=(0,5))
        generate_button = customtkinter.CTkButton(password_frame, text="Generate", width=80, corner_radius=10, fg_color="#7B6CFF", hover_color="#9B8CFF",
                                                command=lambda: self.generate_password_window(password_entry))
        generate_button.pack(side="left")


        save_button = customtkinter.CTkButton(main_frame, text="Save Changes", width=120, corner_radius=10, fg_color="#7B6CFF", hover_color="#9B8CFF",
                                            command=lambda: self.save_edited_password(website, website_entry, username_entry, password_entry, category_entry, tags_entry, vault_menu, edit_window))
        save_button.pack(pady=20)

    def save_edited_password(self, old_website, website_entry, username_entry, password_entry, category_entry, tags_entry, vault_menu, window):
        new_website = website_entry.get().lower()
        new_username = username_entry.get()
        new_password = password_entry.get()
        new_category = category_entry.get()
        new_tags = [tag.strip() for tag in tags_entry.get().split(',')]
        new_vault = vault_menu.get()

        if not new_website or not new_username or not new_password:
            messagebox.showerror("Error", "Please fill in all fields.", parent=window)
            return

        with open(self.data_file, 'r') as f:
            data = json.load(f)

        if old_website in data:
            del data[old_website]

        new_entry = {"username": new_username, "password": new_password, "category": new_category, "tags": new_tags, "vault": new_vault}
        encrypted_entry = encrypt_data(new_entry, self.stored_main_password_hash)
        data[new_website] = encrypted_entry.decode('utf-8')

        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Success", "Changes saved successfully!", parent=window)
        self.load_passwords_into_ui()
        self.load_sidebar()
        self.display_details(new_website, new_username, new_password, new_category, new_tags, new_vault)
        window.destroy()

    def delete_password(self, website_to_delete):
        if not messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the password for {website_to_delete}?"):
            return

        with open(self.data_file, 'r') as f:
            data = json.load(f)

        if website_to_delete.lower() in data:
            del data[website_to_delete.lower()]

        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Success", "Password deleted successfully!")
        self.load_passwords_into_ui()
        self.load_sidebar()

        for widget in self.detail_panel_frame.winfo_children():
            widget.destroy()


    def load_passwords_into_ui(self, search_term=None, category_filter=None, vault_filter=None):
        for widget in self.favorites_list.winfo_children():
            widget.destroy()

        try:
            with open(self.data_file, 'r') as f:
                password_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            password_data = {}

        for website, encrypted_credential in password_data.items():
            try:
                decrypted_credential = decrypt_data(encrypted_credential.encode('utf-8'), self.stored_main_password_hash)
                if not decrypted_credential: continue

                username = decrypted_credential.get('username', '')
                password = decrypted_credential.get('password', '')
                category = decrypted_credential.get('category', '')
                tags = decrypted_credential.get('tags', [])
                vault = decrypted_credential.get('vault', 'Default')

                if search_term:
                    if search_term.lower() not in website.lower() and \
                       search_term.lower() not in username.lower() and \
                       search_term.lower() not in category.lower() and \
                       search_term.lower() not in "".join(tags).lower():
                       continue

                if category_filter and category != category_filter:
                    continue

                if vault_filter and vault != vault_filter:
                    continue


                item_frame = customtkinter.CTkFrame(self.favorites_list, fg_color="#181a1f", corner_radius=10)
                item_frame.pack(fill="x", pady=5, padx=5)

                name_label = customtkinter.CTkLabel(item_frame, text=website.capitalize(), font=("Poppins", 14))
                name_label.pack(side="left", padx=10, pady=10)
                email_label = customtkinter.CTkLabel(item_frame, text=username, font=("Poppins", 12), text_color="gray")
                email_label.pack(side="left", padx=10, pady=10)

                copy_icon = customtkinter.CTkButton(item_frame, text="📄", font=("Poppins", 16), width=30, fg_color="transparent", hover=False,
                                                    command=lambda p=password: self.copy_to_clipboard(p))
                copy_icon.pack(side="right", padx=10, pady=10)

                item_frame.bind("<Button-1>", lambda event, w=website, u=username, p=password, c=category, t=tags, v=vault: self.display_details(w, u, p, c, t, v))
                name_label.bind("<Button-1>", lambda event, w=website, u=username, p=password, c=category, t=tags, v=vault: self.display_details(w, u, p, c, t, v))
                email_label.bind("<Button-1>", lambda event, w=website, u=username, p=password, c=category, t=tags, v=vault: self.display_details(w, u, p, c, t, v))

            except (ValueError, AttributeError, TypeError) as e:
                print(e)
                continue

    def display_details(self, website, username, password, category, tags, vault):
        for widget in self.detail_panel_frame.winfo_children():
            widget.destroy()

        detail_title = customtkinter.CTkLabel(self.detail_panel_frame, text=website.capitalize(), font=("Poppins", 20, "bold"))
        detail_title.pack(pady=20, padx=20, anchor="w")

        fields = {
            "Usuario/Email": username,
            "Contraseña": "••••••••••••",
            "Sitio web/App": f"{website}.com",
            "Vault": vault,
            "Categoría": category,
        }

        for label_text, value_text in fields.items():
            field_frame = customtkinter.CTkFrame(self.detail_panel_frame, fg_color="transparent")
            field_frame.pack(fill="x", padx=20, pady=10, anchor="w")

            label = customtkinter.CTkLabel(field_frame, text=label_text, font=("Poppins", 12), text_color="gray")
            label.pack(anchor="w")

            value_frame = customtkinter.CTkFrame(field_frame, fg_color="transparent")
            value_frame.pack(fill="x")

            value = customtkinter.CTkLabel(value_frame, text=value_text, font=("Poppins", 14))
            value.pack(side="left", anchor="w")

            if label_text == "Contraseña":
                copy_button = customtkinter.CTkButton(value_frame, text="📄", font=("Poppins", 16), width=30, fg_color="transparent", hover=False,
                                                      command=lambda p=password: self.copy_to_clipboard(p))
                copy_button.pack(side="left", padx=10)


        tags_frame = customtkinter.CTkFrame(self.detail_panel_frame, fg_color="transparent")
        tags_frame.pack(fill="x", padx=20, pady=10, anchor="w")
        tags_label = customtkinter.CTkLabel(tags_frame, text="Tags", font=("Poppins", 12), text_color="gray")
        tags_label.pack(anchor="w", pady=(0,5))

        tag_buttons_frame = customtkinter.CTkFrame(tags_frame, fg_color="transparent")
        tag_buttons_frame.pack(fill="x")
        for tag in tags:
            tag_button = customtkinter.CTkButton(tag_buttons_frame, text=tag, fg_color="#7B6CFF", hover=False, corner_radius=10, font=("Poppins", 10))
            tag_button.pack(side="left", padx=(0,5))

        actions_frame = customtkinter.CTkFrame(self.detail_panel_frame, fg_color="transparent")
        actions_frame.pack(fill="x", padx=20, pady=20, anchor="s")

        edit_button = customtkinter.CTkButton(actions_frame, text="Editar", fg_color="#7B6CFF", corner_radius=10,
                                            command=lambda: self.edit_password_window(website, username, password, category, tags, vault))
        edit_button.pack(side="left", padx=5)

        delete_button = customtkinter.CTkButton(actions_frame, text="Delete", fg_color="#ff4d4d", corner_radius=10,
                                              command=lambda: self.delete_password(website))
        delete_button.pack(side="left", padx=5)

        favorite_button = customtkinter.CTkButton(actions_frame, text="⭐", fg_color="transparent", font=("Poppins", 20))
        favorite_button.pack(side="right", padx=5)

    def copy_to_clipboard(self, text):
        clipboard.copy(text)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def import_passwords(self):
        filepath = filedialog.askopenfilename(
            title="Select a CSV file to import",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        try:
            with open(filepath, 'r', newline='') as csvfile:
                reader = csv.reader(csvfile)
                header = next(reader)

                count = 0
                for row in reader:
                    website = row[0]
                    username = row[1]
                    password = row[2]
                    category = row[3] if len(row) > 3 else "Uncategorized"
                    tags = [tag.strip() for tag in row[4].split(',')] if len(row) > 4 else []
                    vault = row[5] if len(row) > 5 else "Default"

                    new_entry = {"username": username, "password": password, "category": category, "tags": tags, "vault": vault}
                    encrypted_entry = encrypt_data(new_entry, self.stored_main_password_hash)
                    data[website.lower()] = encrypted_entry.decode('utf-8')
                    count += 1

            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=4)

            messagebox.showinfo("Success", f"{count} passwords imported successfully!")
            self.load_passwords_into_ui()
            self.load_sidebar()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during import: {e}")


    def export_passwords(self):
        filepath = filedialog.asksaveasfilename(
            title="Select a location to export the CSV file",
            defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        try:
            with open(self.data_file, 'r') as f:
                password_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            password_data = {}

        try:
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Website", "Username", "Password", "Category", "Tags", "Vault"])

                for website, encrypted_credential in password_data.items():
                    decrypted_credential = decrypt_data(encrypted_credential.encode('utf-8'), self.stored_main_password_hash)
                    if not decrypted_credential: continue

                    username = decrypted_credential.get('username', '')
                    password = decrypted_credential.get('password', '')
                    category = decrypted_credential.get('category', '')
                    tags = decrypted_credential.get('tags', [])
                    vault = decrypted_credential.get('vault', 'Default')
                    writer.writerow([website, username, password, category, ", ".join(tags), vault])

            messagebox.showinfo("Success", "Passwords exported successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during export: {e}")

    def generate_password_window(self, password_entry):
        gen_window = customtkinter.CTkToplevel(self)
        gen_window.title("Generate Password")
        gen_window.geometry("350x300")
        gen_window.transient(self)
        gen_window.grab_set()

        main_frame = customtkinter.CTkFrame(gen_window, fg_color="#141418")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        length_label = customtkinter.CTkLabel(main_frame, text="Length:")
        length_label.pack(pady=(10,0))
        length_slider = customtkinter.CTkSlider(main_frame, from_=8, to=32, number_of_steps=24)
        length_slider.set(12)
        length_slider.pack()

        uppercase_var = customtkinter.BooleanVar(value=True)
        uppercase_check = customtkinter.CTkCheckBox(main_frame, text="Include Uppercase", variable=uppercase_var)
        uppercase_check.pack(pady=5)

        lowercase_var = customtkinter.BooleanVar(value=True)
        lowercase_check = customtkinter.CTkCheckBox(main_frame, text="Include Lowercase", variable=lowercase_var)
        lowercase_check.pack(pady=5)

        digits_var = customtkinter.BooleanVar(value=True)
        digits_check = customtkinter.CTkCheckBox(main_frame, text="Include Digits", variable=digits_var)
        digits_check.pack(pady=5)

        symbols_var = customtkinter.BooleanVar(value=True)
        symbols_check = customtkinter.CTkCheckBox(main_frame, text="Include Symbols", variable=symbols_var)
        symbols_check.pack(pady=5)

        def generate_and_apply():
            length = int(length_slider.get())
            use_uppercase = uppercase_var.get()
            use_lowercase = lowercase_var.get()
            use_digits = digits_var.get()
            use_symbols = symbols_var.get()

            try:
                password = generate_random_password(length, use_uppercase, use_lowercase, use_digits, use_symbols)
                password_entry.delete(0, 'end')
                password_entry.insert(0, password)
                gen_window.destroy()
            except ValueError as e:
                messagebox.showerror("Error", str(e), parent=gen_window)

        generate_button = customtkinter.CTkButton(main_frame, text="Generate", width=100, corner_radius=10, fg_color="#7B6CFF", hover_color="#9B8CFF",
                                                command=generate_and_apply)
        generate_button.pack(pady=20)

    def search_passwords(self, event=None):
        search_term = self.search_bar.get()
        self.load_passwords_into_ui(search_term=search_term)

    def filter_by_category(self, category):
        self.load_passwords_into_ui(category_filter=category)

    def filter_by_vault(self, vault):
        self.load_passwords_into_ui(vault_filter=vault)

    def manage_vaults_window(self):
        manage_window = customtkinter.CTkToplevel(self)
        manage_window.title("Manage Vaults")
        manage_window.geometry("400x300")
        manage_window.transient(self)
        manage_window.grab_set()

        main_frame = customtkinter.CTkFrame(manage_window, fg_color="#141418")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        vault_list_frame = customtkinter.CTkScrollableFrame(main_frame, fg_color="transparent")
        vault_list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        def refresh_vault_list():
            for widget in vault_list_frame.winfo_children():
                widget.destroy()
            for vault in self.vaults:
                vault_frame = customtkinter.CTkFrame(vault_list_frame, fg_color="#181a1f", corner_radius=10)
                vault_frame.pack(fill="x", pady=5)

                vault_label = customtkinter.CTkLabel(vault_frame, text=vault)
                vault_label.pack(side="left", padx=10)

                if vault != "Default":
                    delete_button = customtkinter.CTkButton(vault_frame, text="Delete", fg_color="#ff4d4d", width=60,
                                                          command=lambda v=vault: delete_vault(v))
                    delete_button.pack(side="right", padx=10)

        refresh_vault_list()

        def add_vault():
            dialog = customtkinter.CTkInputDialog(text="Enter new vault name:", title="Add Vault")
            new_vault = dialog.get_input()
            if new_vault and new_vault not in self.vaults:
                self.vaults.append(new_vault)
                refresh_vault_list()
                self.load_sidebar()

        def delete_vault(vault_to_delete):
            if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the vault '{vault_to_delete}'? This will move all its passwords to the 'Default' vault."):

                try:
                    with open(self.data_file, 'r') as f:
                        password_data = json.load(f)
                except (FileNotFoundError, json.JSONDecodeError):
                    password_data = {}

                for website, encrypted_credential in password_data.items():
                    decrypted_credential = decrypt_data(encrypted_credential.encode('utf-8'), self.stored_main_password_hash)
                    if decrypted_credential and decrypted_credential.get('vault') == vault_to_delete:
                        decrypted_credential['vault'] = 'Default'
                        encrypted_entry = encrypt_data(decrypted_credential, self.stored_main_password_hash)
                        password_data[website] = encrypted_entry.decode('utf-8')

                with open(self.data_file, 'w') as f:
                    json.dump(password_data, f, indent=4)

                self.vaults.remove(vault_to_delete)
                refresh_vault_list()
                self.load_sidebar()
                self.load_passwords_into_ui()


        add_button = customtkinter.CTkButton(main_frame, text="Add Vault", command=add_vault)
        add_button.pack(pady=10)


if __name__ == '__main__':
    app = PasswordManagerUI("data/password_data.json", "data/main_password.pickle", os.urandom(16), "453607")
    app.mainloop()
