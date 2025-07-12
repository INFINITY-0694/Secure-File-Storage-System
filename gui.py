import sys
import os
import json
import time
import webbrowser
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QLineEdit,
    QInputDialog, QMessageBox, QSpinBox
)
from PyQt5.QtCore import Qt, QMimeData
from PyQt5.QtGui import QFont, QDragEnterEvent, QDropEvent, QIcon

from crypto_utils import encrypt_file, decrypt_file, sha256_hash

FILES_DIR = "files"
META_FILE = "metadata.json"
# ===== Developer Config =====
TITLE_FONT_SIZE = 40  # ← Change this value to increase or decrease title size

class SecureStorageGUI(QWidget):
    def __init__(self, title_font_size=36):
        super().__init__()
        self.title_font_size = title_font_size
        self.setWindowTitle("🔐 Secure File Storage System (AES-256)")
        self.setGeometry(300, 100, 480, 620)
        self.setAcceptDrops(True)

        if not os.path.exists(FILES_DIR):
            os.makedirs(FILES_DIR)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(30, 30, 30, 20)

        # ======= TITLE =======
        self.title_label = QLabel("🔐 AES-256 Secure File Storage System")
        self.title_label.setFont(QFont("Segoe UI", TITLE_FONT_SIZE, QFont.Bold))
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("color: #f1c40f; margin-bottom: 10px;")
        layout.addWidget(self.title_label)

        # ======= FONT SIZE CHANGER =======
        font_size_layout = QHBoxLayout()
        font_size_label = QLabel("🖋️ Title Font Size:")
        font_size_label.setFont(QFont("Segoe UI", 10))

        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(20, 72)
        self.font_size_spin.setValue(self.title_font_size)
        self.font_size_spin.valueChanged.connect(self.update_title_font)

        font_size_layout.addStretch()
        font_size_layout.addWidget(font_size_label)
        font_size_layout.addWidget(self.font_size_spin)
        font_size_layout.addStretch()
        layout.addLayout(font_size_layout)

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

        # ======= FOOTER: Developer =======
        footer_label = QLabel("Developed by DIVY R SONI")
        footer_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        footer_label.setAlignment(Qt.AlignCenter)
        footer_label.setStyleSheet("margin-top: 18px;")
        layout.addWidget(footer_label)

        social_links = QHBoxLayout()
        social_links.setSpacing(20)

        linkedin_btn = QPushButton()
        linkedin_btn.setIcon(QIcon("linkedin.png"))
        linkedin_btn.setToolTip("LinkedIn")
        linkedin_btn.clicked.connect(lambda: webbrowser.open("https://www.linkedin.com/in/divy-soni0694/"))
        linkedin_btn.setIconSize(linkedin_btn.sizeHint())
        linkedin_btn.setFixedSize(36, 36)

        github_btn = QPushButton()
        github_btn.setIcon(QIcon("github.png"))
        github_btn.setToolTip("GitHub")
        github_btn.clicked.connect(lambda: webbrowser.open("https://github.com/INFINITY-0694"))
        github_btn.setIconSize(github_btn.sizeHint())
        github_btn.setFixedSize(36, 36)

        instagram_btn = QPushButton()
        instagram_btn.setIcon(QIcon("instagram.png"))
        instagram_btn.setToolTip("Instagram")
        instagram_btn.clicked.connect(lambda: webbrowser.open("https://www.instagram.com/"))  # Optional
        instagram_btn.setIconSize(instagram_btn.sizeHint())
        instagram_btn.setFixedSize(36, 36)

        social_links.addStretch()
        social_links.addWidget(linkedin_btn)
        social_links.addWidget(github_btn)
        social_links.addWidget(instagram_btn)
        social_links.addStretch()
        layout.addLayout(social_links)

        # ======= FOOTER TEXT =======
        footer_note = QLabel(
            "Built with PyQt5 + AES-256 + SHA-256 Hashing | Version 1.0.0\n"
            "This tool provides local file security. It does not guarantee protection against physical access or external threats.\n"
            "© 2025. All rights reserved. 📬 Contact: divysoniofficial@gmail.com"
        )
        footer_note.setFont(QFont("Segoe UI", 8))
        footer_note.setAlignment(Qt.AlignCenter)
        footer_note.setStyleSheet("color: #888888; margin-top: 10px;")
        layout.addWidget(footer_note)

        self.setLayout(layout)
        self.apply_dark_theme()

    def update_title_font(self, new_size):
        self.title_label.setFont(QFont("Segoe UI", new_size, QFont.Bold))

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
        return QInputDialog.getText(self, "Password Required", prompt, QLineEdit.Password)

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
        metadata[file_name] = {"sha256": sha256, "timestamp": timestamp}
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
        self.show_success("Folder decryption completed.")

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent):
        for url in e.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path and os.path.isfile(file_path):
                self.encrypt_logic(file_path)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = SecureStorageGUI(title_font_size=36)
    window.show()
    sys.exit(app.exec_())
