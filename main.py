import os
from ui import PasswordManagerUI
import customtkinter

def main():
    pattern = "453607"
    salt = os.urandom(16)
    main_password_file = 'data/main_password.pickle'
    data_file = 'data/password_data.pickle'

    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists('data/files'):
        os.makedirs('data/files')

    customtkinter.set_appearance_mode("System")
    customtkinter.set_default_color_theme("blue")
    
    app = PasswordManagerUI(data_file, main_password_file, salt, pattern)
    app.mainloop()

if __name__ == "__main__":
    main()
