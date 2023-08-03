# Python Password Manager and File Encryption/Decryption App

![Password Manager Logo](icon.ico)

This is a Python password manager and file encryption/decryption app that provides a secure way to manage your credentials and encrypt/decrypt files using three layers of protection: hashing, encryption, and storage.

## Features

1. **Password Management**
   - Add, view, edit, and delete credentials securely.
   - Hashed passwords are stored to ensure enhanced security.

2. **File Encryption/Decryption**
   - Encrypt and decrypt all types of files, including images, videos, and more.
   - Files are securely encrypted before being stored.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/imlogeshmohan/Password-Manager.git
cd password-manager
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Navigate to the `data/files` directory and place the files you want to encrypt in this folder.

2. To run the app, execute the following command:

```bash
python main.py
```

3. Follow the on-screen instructions to manage your credentials or encrypt/decrypt files.

## Security

The password manager utilizes three layers of protection to ensure the security of your data:

1. **Hashing**: User passwords are hashed and encryped before storage using a strong cryptographic hashing algorithm. This ensures that passwords are never stored in plain text, providing an additional layer of security.

2. **Encryption**: All files placed in the `data/files` directory are encrypted using a secure encryption algorithm before being stored in the app. This ensures that your sensitive files remain protected.

3. **Storage**: Encrypted passwords and files are securely stored in the `data` folder. Ensure that you keep this folder protected and back up your data regularly to prevent data loss.

## Contributions

Contributions to this project are welcome! If you find any issues or have suggestions for improvement, feel free to open an issue or create a pull request.

## Disclaimer

This app is provided as-is and does not come with any warranties. It is your responsibility to use this app in compliance with relevant laws and regulations. The developers are not responsible for any data breaches or data loss resulting from the use of this app.

## License

This project is licensed under the [MIT License](LICENSE).

---

We hope you find this password manager and file encryption/decryption app helpful for securing your sensitive data. If you have any questions or need assistance, feel free to reach out to us.

Happy secure password managing and file encryption! 🚀
