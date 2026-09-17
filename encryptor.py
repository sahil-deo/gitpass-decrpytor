import csv
import base64
import os
import sys
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


def enc(data, password):
    """Encrypt data using AES-GCM with PBKDF2 key derivation."""
    data = data.encode()
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_blob = salt + cipher.nonce + tag + ciphertext
    encrypted_b64 = base64.b64encode(encrypted_blob).decode()
    return encrypted_b64


def denc(data, password):
    """Decrypt data using AES-GCM with PBKDF2 key derivation."""
    raw = base64.b64decode(data)
    salt, nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:48], raw[48:]
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


def has_header_row(csv_path):
    """Check if CSV file has a header row by examining the first row."""
    try:
        with open(csv_path, 'r', encoding='utf-8', newline='') as file:
            reader = csv.reader(file)
            first_row = next(reader, None)
            if first_row:
                browser_headers = [
                    'url', 'username', 'password', 'httprealm', 'formactionorigin',
                    'guid', 'timecreated', 'timelastused', 'timepasswordchanged'
                ]
                return any(header.lower() in [cell.lower() for cell in first_row] for header in browser_headers)
    except Exception:
        pass
    return False


def process_csv_for_encryption(csv_path):
    """Read CSV and keep only url, username, password fields."""
    try:
        data_rows = []

        with open(csv_path, 'r', encoding='utf-8', newline='') as file:
            reader = csv.reader(file)
            rows = list(reader)

        if not rows:
            return "[]"

        if has_header_row(csv_path) and rows:
            header = [cell.lower().strip() for cell in rows[0]]
            data_start = 1
        else:
            header = ['url', 'username', 'password', 'httprealm', 'formactionorigin', 'guid', 'timecreated', 'timelastused', 'timepasswordchanged']
            data_start = 0

        url_idx = None
        username_idx = None
        password_idx = None

        for i, col in enumerate(header):
            col_lower = col.lower().strip()
            if col_lower == 'url':
                url_idx = i
            elif col_lower in ['username', 'user']:
                username_idx = i
            elif col_lower == 'password':
                password_idx = i

        if url_idx is None:
            url_idx = 0
        if username_idx is None:
            username_idx = 1
        if password_idx is None:
            password_idx = 2

        clean_header = ["url", "username", "password"]
        data_rows.append(clean_header)

        for row in rows[data_start:]:
            if len(row) > max(url_idx, username_idx, password_idx):
                extracted_row = [
                    row[url_idx] if url_idx < len(row) else "",
                    row[username_idx] if username_idx < len(row) else "",
                    row[password_idx] if password_idx < len(row) else ""
                ]
                data_rows.append(extracted_row)

        return str(data_rows)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return None


def encrypt_text(text, password):
    """Encrypt any text payload using the app's AES-GCM encryption."""
    return enc(text, password)


def decrypt_text(encrypted_text, password):
    """Decrypt any text payload using the app's AES-GCM encryption."""
    return denc(encrypted_text, password)


def write_text_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def read_text_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def encrypt_passwords_csv(csv_path, output_path="enc_password.txt"):
    """Encrypt a password-export CSV to a text blob."""
    csv_content = process_csv_for_encryption(csv_path)
    if csv_content is None:
        return False

    password = getpass("Enter encryption password: ")
    if not password:
        print("Error: Password cannot be empty!")
        return False

    encrypted_data = enc(csv_content, password)
    write_text_file(output_path, encrypted_data)
    print("✓ Passwords encrypted successfully!")
    print(f"✓ Encrypted data saved to: {output_path}")
    return True


def decrypt_passwords_csv(file_path, output_path="passwords.csv"):
    """Decrypt a password-export blob back to a CSV with browser-like headers."""
    try:
        encrypted_data = read_text_file(file_path).strip()
        password = getpass("Enter decryption password: ")
        if not password:
            print("Error: Password cannot be empty!")
            return False

        decrypted_content = denc(encrypted_data, password)
        import ast
        data_rows = ast.literal_eval(decrypted_content)

        if data_rows and data_rows[0] == ["url", "username", "password"]:
            password_data = data_rows[1:]
        else:
            password_data = data_rows

        full_header = [
            "url", "username", "password", "httpRealm", "formActionOrigin", "guid",
            "timeCreated", "timeLastUsed", "timePasswordChanged"
        ]

        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(full_header)

            for row in password_data:
                if len(row) >= 3:
                    writer.writerow([
                        row[0],
                        row[1],
                        row[2],
                        "",
                        "",
                        "",
                        "",
                        "",
                        ""
                    ])

        print("✓ Passwords decrypted successfully!")
        print(f"✓ Decrypted CSV saved to: {output_path}")
        return True
    except Exception as e:
        print(f"Error during decryption: {e}")
        print("This could be due to wrong password or corrupted data.")
        return False


def encrypt_notes_file(input_path, output_path="enc_notes.txt"):
    """Encrypt a plain text notes file."""
    if not os.path.exists(input_path):
        print("Error: File not found!")
        return False

    password = getpass("Enter encryption password: ")
    if not password:
        print("Error: Password cannot be empty!")
        return False

    content = read_text_file(input_path)
    encrypted = enc(content, password)
    write_text_file(output_path, encrypted)
    print("✓ Notes encrypted successfully!")
    print(f"✓ Encrypted data saved to: {output_path}")
    return True


def decrypt_notes_file(input_path, output_path="notes.txt"):
    """Decrypt a notes file previously encrypted by this tool."""
    if not os.path.exists(input_path):
        print("Error: File not found!")
        return False

    password = getpass("Enter decryption password: ")
    if not password:
        print("Error: Password cannot be empty!")
        return False

    try:
        encrypted_data = read_text_file(input_path).strip()
        decrypted = denc(encrypted_data, password)
        write_text_file(output_path, decrypted)
        print("✓ Notes decrypted successfully!")
        print(f"✓ Decrypted notes saved to: {output_path}")
        return True
    except Exception as e:
        print(f"Error during decryption: {e}")
        print("This could be due to wrong password or corrupted data.")
        return False


def main():
    """Main CLI menu for password and notes encryption/decryption."""
    print("GitPass CLI - Encrypt/Decrypt Passwords and Notes")
    print("=" * 52)

    while True:
        print("\nOptions:")
        print("1. Encrypt password CSV")
        print("2. Decrypt password CSV")
        print("3. Encrypt notes file")
        print("4. Decrypt notes file")
        print("5. Exit")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == '1':
            csv_path = input("Enter path to CSV file: ").strip()
            if os.path.exists(csv_path):
                encrypt_passwords_csv(csv_path)
            else:
                print("Error: File not found!")

        elif choice == '2':
            file_path = input("Enter path to encrypted file: ").strip()
            if os.path.exists(file_path):
                decrypt_passwords_csv(file_path)
            else:
                print("Error: File not found!")

        elif choice == '3':
            input_path = input("Enter path to plain notes file: ").strip()
            encrypt_notes_file(input_path)

        elif choice == '4':
            input_path = input("Enter path to encrypted notes file: ").strip()
            decrypt_notes_file(input_path)

        elif choice == '5':
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
