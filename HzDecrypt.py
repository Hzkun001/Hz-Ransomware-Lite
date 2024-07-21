from Crypto.Cipher import AES
import tkinter as tk
from tkinter import filedialog
import os

def hex_to_bytes(hex_string):
    """Convert hexadecimal string to bytes."""
    return bytes.fromhex(hex_string)

def decrypt_file(input_file, output_file, key, nonce):
    try:
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        print(f"Decrypted file saved to {output_file}")

        # Remove the encrypted file
        try:
            os.remove(input_file)
            print(f"Encrypted file {input_file} has been deleted.")
        except Exception as e:
            print(f"Failed to delete encrypted file: {e}")

    except Exception as e:
        print(f"Decryption failed: {e}")

def get_key_nonce_extension():
    """Prompt user to input key and nonce."""
    info_file = filedialog.askopenfilename(title="Select Encryption Info File", filetypes=[("Text files", "*.txt")])
    if not info_file:
        print("No file selected.")
        return None, None

    key_nonce_extension_dict = {}
    with open(info_file, 'r') as f:
        lines = f.readlines()
        for i in range(0, len(lines), 6):
            original_file_name = lines[i + 1].strip().split(": ")[1]
            key_hex = lines[i + 2].strip().split(": ")[1]
            nonce_hex = lines[i + 3].strip().split(": ")[1]
            extension = lines[i + 4].strip().split(": ")[1]
            key_nonce_extension_dict[original_file_name] = (key_hex, nonce_hex, extension)
    
    return key_nonce_extension_dict

def decrypt_all_files_in_directory(directory, key_nonce_extension_dict):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".hzexploit"):  # Check for .hz extension
                input_file = os.path.join(root, file)
                original_file_name = file[:-10]  # Remove .hz extension
                key_hex, nonce_hex, extension = key_nonce_extension_dict.get(original_file_name, (None, None, None))
                if key_hex and nonce_hex and extension:
                    key = hex_to_bytes(key_hex)
                    nonce = hex_to_bytes(nonce_hex)
                    output_file = os.path.join(root, original_file_name)
                    decrypt_file(input_file, output_file, key, nonce)
                else:
                    print(f"No decryption info for {original_file_name}")

def choose_directory_to_decrypt():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    
    directory = filedialog.askdirectory(title="Select Directory to Decrypt")
    if not directory:
        print("No directory selected.")
        return

    key_nonce_extension_dict = get_key_nonce_extension()
    if not key_nonce_extension_dict:
        print("Failed to get key, nonce, or extension.")
        return
    
    decrypt_all_files_in_directory(directory, key_nonce_extension_dict)

if __name__ == "__main__":
    choose_directory_to_decrypt()
