import csv
import base64
import os
import sys
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def enc(data, password):
    """Encrypt data using AES-GCM with PBKDF2 key derivation"""
    data = data.encode()
    # Derive key
    salt = get_random_bytes(16)  # random salt, store this
    key = PBKDF2(password, salt, dkLen=32)
    # Encrypt
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Combine salt + nonce + tag + ciphertext
    encrypted_blob = salt + cipher.nonce + tag + ciphertext
    # Encode to base64 for storage/transmission
    encrypted_b64 = base64.b64encode(encrypted_blob).decode()
    return encrypted_b64

def denc(data, password):
    """Decrypt data using AES-GCM with PBKDF2 key derivation"""
    # Decode from base64 to binary
    raw = base64.b64decode(data)  # decode before splitting
    # Extract parts
    salt, nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:48], raw[48:]
    key = PBKDF2(password, salt, dkLen=32)
    # Decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

def has_header_row(csv_path):
    """Check if CSV file has a header row by examining first row"""
    try:
        with open(csv_path, 'r', encoding='utf-8', newline='') as file:
            reader = csv.reader(file)
            first_row = next(reader, None)
            if first_row:
                # Browser password export headers
                browser_headers = ['url', 'username', 'password', 'httprealm', 'formactionorigin', 'guid', 'timecreated', 'timelastused', 'timepasswordchanged']
                return any(header.lower() in [cell.lower() for cell in first_row] for header in browser_headers)
    except Exception:
        pass
    return False

def process_csv_for_encryption(csv_path):
    """Read CSV file, extract ONLY url, username, password fields and create clean CSV data"""
    try:
        data_rows = []
        
        with open(csv_path, 'r', encoding='utf-8', newline='') as file:
            reader = csv.reader(file)
            rows = list(reader)
        
        if not rows:
            return "[]"
        
        # Check if we need to remove header and find column indices
        if has_header_row(csv_path) and rows:
            header = [cell.lower().strip() for cell in rows[0]]
            data_start = 1
        else:
            # Assume standard browser export order: url, username, password, httpRealm, formActionOrigin, guid, timeCreated, timeLastUsed, timePasswordChanged
            header = ['url', 'username', 'password', 'httprealm', 'formactionorigin', 'guid', 'timecreated', 'timelastused', 'timepasswordchanged']
            data_start = 0
        
        # Find indices for url, username, password
        url_idx = None
        username_idx = None
        password_idx = None
        
        # Print header for debugging
        print(f"DEBUG: Detected header: {header}")
        
        for i, col in enumerate(header):
            col_lower = col.lower().strip()
            if col_lower == 'url':
                url_idx = i
            elif col_lower in ['username', 'user']:
                username_idx = i
            elif col_lower == 'password':
                password_idx = i
        
        # If we can't find the columns, assume standard browser order: url(0), username(1), password(2)
        if url_idx is None:
            url_idx = 0
            print("WARNING: URL column not found, assuming index 0")
        if username_idx is None:
            username_idx = 1
            print("WARNING: Username column not found, assuming index 1")
        if password_idx is None:
            password_idx = 2
            print("WARNING: Password column not found, assuming index 2")
        
        print(f"DEBUG: Using indices - URL: {url_idx}, Username: {username_idx}, Password: {password_idx}")
        
        # Add clean header row with only the 3 fields we want
        clean_header = ["url", "username", "password"]
        data_rows.append(clean_header)
        
        # Extract only url, username, password from each data row
        for row in rows[data_start:]:
            if len(row) > max(url_idx, username_idx, password_idx):
                extracted_row = [
                    row[url_idx] if url_idx < len(row) else "",
                    row[username_idx] if username_idx < len(row) else "",
                    row[password_idx] if password_idx < len(row) else ""
                ]
                data_rows.append(extracted_row)
                
                # Debug first few rows
                if len(data_rows) <= 3:
                    print(f"DEBUG: Row {len(data_rows)} - URL: '{extracted_row[0]}', Username: '{extracted_row[1]}', Password: '{extracted_row[2][:10]}...'")
        
        print(f"DEBUG: Processed {len(data_rows)-1} data rows (plus header)")
        
        # Convert list of lists to string representation
        list_string = str(data_rows)
        
        return list_string
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return None

def encrypt_passwords():
    """Encrypt password CSV file"""
    csv_path = input("Enter path to CSV file: ").strip()
    
    if not os.path.exists(csv_path):
        print("Error: File not found!")
        return
    
    # Read and process CSV
    csv_content = process_csv_for_encryption(csv_path)
    if csv_content is None:
        return
    
    # Get password
    password = getpass("Enter encryption password: ")
    if not password:
        print("Error: Password cannot be empty!")
        return
    
    try:
        # Encrypt the content
        encrypted_data = enc(csv_content, password)
        
        # Write to file
        with open('enc_password.txt', 'w') as f:
            f.write(encrypted_data)
        
        print("✓ Passwords encrypted successfully!")
        print("✓ Encrypted data saved to: enc_password.txt")
        print(f"✓ Original file processed - only URL, Username, Password fields retained")
        print(f"✓ All other headers and data columns removed before encryption")
        
    except Exception as e:
        print(f"Error during encryption: {e}")

def decrypt_passwords():
    """Decrypt password file and convert back to CSV with full browser headers"""
    file_path = input("Enter path to encrypted file: ").strip()
    
    if not os.path.exists(file_path):
        print("Error: File not found!")
        return
    
    try:
        # Read encrypted data
        with open(file_path, 'r') as f:
            encrypted_data = f.read().strip()
        
        # Get password
        password = getpass("Enter decryption password: ")
        if not password:
            print("Error: Password cannot be empty!")
            return
        
        # Decrypt
        decrypted_content = denc(encrypted_data, password)
        
        # Convert string representation back to list of lists
        import ast
        data_rows = ast.literal_eval(decrypted_content)
        
        # Remove the clean header from decrypted data (first row)
        if data_rows and data_rows[0] == ["url", "username", "password"]:
            password_data = data_rows[1:]  # Skip the clean header
        else:
            password_data = data_rows
        
        # Add browser-compatible header row (actual browser export format)
        full_header = ["url", "username", "password", "httpRealm", "formActionOrigin", "guid", "timeCreated", "timeLastUsed", "timePasswordChanged"]
        
        # Write to CSV file with full browser headers
        with open('passwords.csv', 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(full_header)  # Write full browser header
            
            # Write data rows with proper column mapping
            for row in password_data:
                if len(row) >= 3:
                    # row contains [url, username, password]
                    # Map to [url, username, password, httpRealm, formActionOrigin, guid, timeCreated, timeLastUsed, timePasswordChanged]
                    full_row = [
                        row[0],  # url
                        row[1],  # username
                        row[2],  # password
                        "",      # httpRealm (empty)
                        "",      # formActionOrigin (empty)
                        "",      # guid (empty)
                        "",      # timeCreated (empty)
                        "",      # timeLastUsed (empty)
                        ""       # timePasswordChanged (empty)
                    ]
                    writer.writerow(full_row)
        
        print("✓ Passwords decrypted successfully!")
        print("✓ Decrypted CSV saved to: passwords.csv")
        print(f"✓ File contains {len(password_data)} rows of password data")
        print("✓ CSV has all browser headers: URL, Username, Password fields filled; others empty")
        
    except Exception as e:
        print(f"Error during decryption: {e}")
        print("This could be due to wrong password or corrupted data.")

def main():
    """Main program loop"""
    print("Password CSV Encryptor/Decryptor - Clean Version")
    print("=" * 45)
    print("Encryption: Removes all headers except URL, Username, Password")
    print("Decryption: Restores full browser headers (extras empty)")
    print("All other columns and their data are removed during encryption")
    
    while True:
        print("\nOptions:")
        print("1. Encrypt CSV file (clean headers)")
        print("2. Decrypt file")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            encrypt_passwords()
        elif choice == '2':
            decrypt_passwords()
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)