import sys
import os
import json
import time
import webbrowser
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QLineEdit,
    QInputDialog, QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from crypto_utils import encrypt_file, decrypt_file, sha256_hash

FILES_DIR = "files"
META_FILE = "metadata.json"

class SecureStorageGUI(QWidget):
    def __init__(self, title_font_size=50):
        super().__init__()
        self.title_font_size = title_font_size
        self.setWindowTitle("🔐 Secure File Storage System (AES-256)")
        self.setGeometry(250, 100, 580, 560)
        self.setAcceptDrops(True)

        if not os.path.exists(FILES_DIR):
            os.makedirs(FILES_DIR)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 15)

        # ======= TITLE =======
        title = QLabel("🔐 AES-256 Secure File Storage System")
        title.setFont(QFont("Segoe UI", self.title_font_size, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #ade8f4; margin-bottom: 18px; font-size : 40 pt")
        layout.addWidget(title)

        # ======= FILE OPTIONS =======
        file_label = QLabel("🗃️ File Operations")
        file_label.setFont(QFont("Segoe UI", 13, QFont.Bold))
        layout.addWidget(file_label)

        file_buttons = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt File")
        self.decrypt_btn = QPushButton("Decrypt File")
        self.encrypt_btn.clicked.connect(self.encrypt_file_ui)
        self.decrypt_btn.clicked.connect(self.decrypt_file_ui)
        file_buttons.addWidget(self.encrypt_btn)
        file_buttons.addWidget(self.decrypt_btn)
        layout.addLayout(file_buttons)

        # ======= FOLDER OPTIONS =======
        folder_label = QLabel("📁 Folder Operations")
        folder_label.setFont(QFont("Segoe UI", 13, QFont.Bold))
        layout.addWidget(folder_label)

        folder_buttons = QHBoxLayout()
        self.encrypt_folder_btn = QPushButton("Encrypt Folder")
        self.decrypt_folder_btn = QPushButton("Decrypt Folder")
        self.encrypt_folder_btn.clicked.connect(self.encrypt_folder_ui)
        self.decrypt_folder_btn.clicked.connect(self.decrypt_folder_ui)
        folder_buttons.addWidget(self.encrypt_folder_btn)
        folder_buttons.addWidget(self.decrypt_folder_btn)
        layout.addLayout(folder_buttons)

        # ======= DRAG & DROP INFO =======
        drag_info = QLabel("⬇️ Drag and Drop files here to encrypt")
        drag_info.setAlignment(Qt.AlignCenter)
        drag_info.setFont(QFont("Segoe UI", 8))
        drag_info.setStyleSheet("font-size: 9pt; color: #aaaaaa;")
        layout.addWidget(drag_info)

        # ======= STATUS =======
        self.status_label = QLabel("")
        self.status_label.setFont(QFont("Consolas", 10))
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # ======= DEVELOPER NAME =======
        dev_label = QLabel("Connect with me:")
        dev_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        dev_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(dev_label)

        # ======= SOCIAL TEXT BUTTONS =======
        social_links = QHBoxLayout()
        #social_links.setSpacing(1)

        linkedin_btn = QPushButton("LinkedIn")
        linkedin_btn.setToolTip("LinkedIn")
        linkedin_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        linkedin_btn.clicked.connect(lambda: webbrowser.open("https://www.linkedin.com/in/divy-soni0694/"))
        linkedin_btn.setFixedSize(90, 35)

        github_btn = QPushButton("GitHub")
        github_btn.setToolTip("GitHub")
        github_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        github_btn.clicked.connect(lambda: webbrowser.open("https://github.com/INFINITY-0694"))
        github_btn.setFixedSize(75, 35)

        instagram_btn = QPushButton("Instagram")
        instagram_btn.setToolTip("Instagram")
        instagram_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        #instagram_btn.setStyleSheet(" font-size: 9pt")
        instagram_btn.clicked.connect(lambda: webbrowser.open("https://www.instagram.com/"))
        instagram_btn.setFixedSize(90, 35)

        social_links.addStretch()
        social_links.addWidget(linkedin_btn)
        social_links.addWidget(github_btn)
        social_links.addWidget(instagram_btn)
        social_links.addStretch()
        layout.addLayout(social_links)

        # ======= FINAL FOOTER =======
        footer_info = QLabel()
        footer_info.setTextFormat(Qt.RichText)
        footer_info.setAlignment(Qt.AlignCenter)
        footer_info.setStyleSheet("color: #aaaaaa; font-size: 9pt; margin-top: 2px;")
        footer_info.setText("""
            <b><h3>Developed by DIVY R SONI</h3></b><br> 
            Built with <b>PyQt5 + AES-256 + SHA-256 Hashing</b> | Version <b>1.0.0</b><br>
            It does not guarantee protection against physical access or external threats.</i> © 2025. All rights reserved.<br>
            📬 Contact: <a style='color:#9ad0ff;' href='mailto:divysoniofficial@gmail.com'>divysoniofficial@gmail.com</a>
        """)
        layout.addWidget(footer_info)

        self.setLayout(layout)
        self.apply_dark_theme()

    def apply_dark_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e2e;
                color: #f8f8f2;
                font-family: 'Segoe UI';
            }
            QPushButton {
                background-color: #313244;
                border: 1px solid #585b70;
                border-radius: 8px;
                padding: 8px 14px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #45475a;
                color: #ffffff;
            }
            QLabel {
                font-size: 12pt;
            }
        """)
        self.status_label.setStyleSheet("color: #8ae9b1;")

    def get_password_dialog(self, prompt):
        password, ok = QInputDialog.getText(self, "Password Required", prompt, QLineEdit.Password)
        return password, ok

    def show_success(self, msg):
        self.status_label.setText("✅ " + msg)
        QMessageBox.information(self, "Success", msg)

    def show_error(self, msg):
        self.status_label.setText("❌ " + msg)
        QMessageBox.critical(self, "Error", msg)

    def save_metadata(self, file_name, sha256, timestamp):
        metadata = {}
        if os.path.exists(META_FILE):
            with open(META_FILE, 'r') as f:
                metadata = json.load(f)
        metadata[file_name] = {
            "sha256": sha256,
            "timestamp": timestamp
        }
        with open(META_FILE, 'w') as f:
            json.dump(metadata, f, indent=4)

    def verify_file_hash(self, file_name, encrypted_data):
        if not os.path.exists(META_FILE):
            return True
        try:
            with open(META_FILE, 'r') as f:
                metadata = json.load(f)
            stored_hash = metadata.get(file_name, {}).get("sha256")
            current_hash = sha256_hash(encrypted_data)
            return stored_hash == current_hash
        except Exception:
            return False

    def encrypt_file_ui(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            self.encrypt_logic(file_path)

    def decrypt_file_ui(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File", directory=FILES_DIR)
        if file_path:
            self.decrypt_logic(file_path)

    def encrypt_logic(self, file_path):
        password, ok = self.get_password_dialog("Enter password to encrypt with")
        if not ok or not password:
            return
        output_name = os.path.basename(file_path) + ".enc"
        output_path = os.path.join(FILES_DIR, output_name)
        try:
            encrypted_data = encrypt_file(file_path, password)
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            file_hash = sha256_hash(encrypted_data)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            self.save_metadata(output_name, file_hash, timestamp)
            self.show_success(f"Encrypted and saved to {output_path}")
        except Exception as e:
            self.show_error(f"Encryption failed: {e}")

    def decrypt_logic(self, file_path):
        password, ok = self.get_password_dialog("Enter password to decrypt")
        if not ok or not password:
            return
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            file_name = os.path.basename(file_path)
            if not self.verify_file_hash(file_name, encrypted_data):
                self.show_error("Integrity check failed! File may be tampered.")
                return
            decrypted_data = decrypt_file(encrypted_data, password)
            output_name = file_name.replace(".enc", ".decrypted")
            output_path = os.path.join(FILES_DIR, output_name)
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            self.show_success(f"Decrypted and saved to {output_path}")
        except ValueError:
            self.show_error("Incorrect password or corrupted file.")
        except Exception as e:
            self.show_error(f"Decryption failed: {e}")

    def encrypt_folder_ui(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Encrypt")
        if not folder_path:
            return
        password, ok = self.get_password_dialog("Enter password to encrypt folder")
        if not ok or not password:
            return
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, folder_path)
                safe_name = rel_path.replace(os.sep, "_")
                output_name = safe_name + ".enc"
                output_path = os.path.join(FILES_DIR, output_name)
                try:
                    encrypted_data = encrypt_file(full_path, password)
                    with open(output_path, 'wb') as f:
                        f.write(encrypted_data)
                    file_hash = sha256_hash(encrypted_data)
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    self.save_metadata(output_name, file_hash, timestamp)
                    self.status_label.setText(f"Encrypted: {rel_path}")
                    QApplication.processEvents()
                except Exception as e:
                    self.show_error(f"Error encrypting {rel_path}: {e}")
                    return
        self.show_success("Folder encrypted successfully.")

    def decrypt_folder_ui(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Save Decrypted Files")
        if not folder_path:
            return
        password, ok = self.get_password_dialog("Enter password to decrypt folder")
        if not ok or not password:
            return
        for file in os.listdir(FILES_DIR):
            if not file.endswith(".enc"):
                continue
            file_path = os.path.join(FILES_DIR, file)
            try:
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                if not self.verify_file_hash(file, encrypted_data):
                    self.show_error(f"Integrity check failed: {file}")
                    continue
                decrypted_data = decrypt_file(encrypted_data, password)
                base_name = file.replace(".enc", "")
                output_path = os.path.join(folder_path, base_name)
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                self.status_label.setText(f"Decrypted: {base_name}")
                QApplication.processEvents()
            except Exception as e:
                self.show_error(f"Error decrypting {file}: {e}")
                continue
        self.show_success("Folder decryption completed.")

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        for url in e.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path and os.path.isfile(file_path):
                self.encrypt_logic(file_path)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = SecureStorageGUI(title_font_size=30)
    window.show()
    sys.exit(app.exec_())
