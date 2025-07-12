import os
import json
import time
from crypto_utils import encrypt_file, decrypt_file, sha256_hash

FILES_DIR = "files"
META_FILE = "metadata.json"

def save_metadata(file_name, sha256, timestamp):
    metadata = {}
    if os.path.exists(META_FILE):
        with open(META_FILE, 'r') as meta:
            metadata = json.load(meta)

    metadata[file_name] = {
        "sha256": sha256,
        "timestamp": timestamp
    }

    with open(META_FILE, 'w') as meta:
        json.dump(metadata, meta, indent=4)
    print(f"[✔] Metadata saved to {META_FILE}")

def encrypt_mode():
    file_path = input("Enter the path to the file to encrypt: ").strip()
    if not os.path.isfile(file_path):
        print("[!] File does not exist.")
        return

    password = input("Enter password to encrypt with: ").strip()
    output_name = os.path.basename(file_path) + ".enc"
    output_path = os.path.join(FILES_DIR, output_name)

    encrypted_data = encrypt_file(file_path, password)

    with open(output_path, 'wb') as out_file:
        out_file.write(encrypted_data)

    print(f"[✔] File encrypted and saved to: {output_path}")

    # Calculate and store hash + metadata
    file_hash = sha256_hash(encrypted_data)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    save_metadata(output_name, file_hash, timestamp)

def decrypt_mode():
    file_name = input("Enter the encrypted file name (in 'files/' folder): ").strip()
    enc_path = os.path.join(FILES_DIR, file_name)

    if not os.path.isfile(enc_path):
        print("[!] Encrypted file not found.")
        return

    password = input("Enter password to decrypt: ").strip()

    with open(enc_path, 'rb') as f:
        encrypted_data = f.read()

    try:
        decrypted_data = decrypt_file(encrypted_data, password)
    except ValueError:
        print("[✘] Incorrect password or corrupted file.")
        return
    except Exception as e:
        print(f"[✘] Unexpected error: {e}")
        return

    # Save decrypted file
    original_name = file_name.replace(".enc", ".decrypted")
    output_path = os.path.join(FILES_DIR, original_name)

    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"[✔] File decrypted and saved as: {output_path}")

def main():
    if not os.path.exists(FILES_DIR):
        os.makedirs(FILES_DIR)

    print("==== Secure File Storage System ====")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Select an option: ").strip()

    if choice == "1":
        encrypt_mode()
    elif choice == "2":
        decrypt_mode()
    else:
        print("[!] Invalid option.")

if __name__ == "__main__":
    main()
