A modern, professional desktop application for **locally encrypting and decrypting files and folders** using **AES-256 encryption** and **SHA-256 hashing**. Built with a PyQt5 GUI, this tool ensures secure and intuitive file handling—perfect for privacy-conscious users.

---

## ✨ Features

- 🔒 **AES-256 Encryption** for strong file and folder security.
- 🧾 **SHA-256 Hashing** for file integrity verification.
- 📂 Supports both **single file** and **entire folder** encryption/decryption.
- 🎯 **Drag-and-drop** functionality.
- 🧑‍💻 Clean and modern **dark-themed GUI** (PyQt5).
- 📁 Auto-organizes encrypted files into a `files/` directory.
- 🖼️ Social icons for developer contact (LinkedIn, GitHub, Instagram).
- 💬 Password-based protection (input at encryption/decryption time).

---

## 📁 Project Structure

SecureFileStorageSystem/
│
├── gui_app.py # Main PyQt5 GUI application
├── crypto_utils.py # AES-256 and SHA-256 encryption/decryption logic
├── main.py # Optional launcher script
├── linkedin.png # Social icon
├── github.png # Social icon
├── instagram.png # Social icon
├── lock.ico # App icon for executable
├── requirements.txt # Python dependencies
├── metadata.json # File integrity database (autogenerated)
├── dist/
│ └── gui_app.exe # Compiled Windows executable (PyInstaller)
└── README.md

---

## 🚀 Getting Started

### 🔧 Installation (for developers)

1. Clone the repository:

```bash
git clone https://github.com/your-username/SecureFileStorageSystem.git
cd SecureFileStorageSystem
```

## 💡 How It Works

Encrypt File/Folder → Select a file/folder → Enter password → Encrypted file is saved with .enc extension.
Decrypt File/Folder → Select .enc file → Enter correct password → Original file is restored.
Hashing → Ensures tamper detection during decryption using SHA-256.
Drag-and-Drop → Instantly encrypt files dropped into the app window.

## 📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

## 🙋‍♂️ Developer
- Divy R Soni

📧 Email: divysoniofficial@gmail.com
LinkedIn : https://www.linkedin.com/in/divy-soni0694
