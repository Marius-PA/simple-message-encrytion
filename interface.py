from encrypt import *
import tkinter as tk
from tkinter import simpledialog, messagebox

def encrypt_message():
    message = simpledialog.askstring("Encrypt", "Enter message to encrypt:")
    if message:
        encrypted = encrypt(message)  # your encryption function
        messagebox.showinfo("Encrypted", encrypted)

def decrypt_message():
    ciphertext = simpledialog.askstring("Decrypt", "Enter message to decrypt:")
    if ciphertext:
        plaintext = decrypt(ciphertext)  # your decryption function
        messagebox.showinfo("Decrypted", plaintext)

root = tk.Tk()
root.title("Encrypt/Decrypt App")

tk.Button(root, text="Encrypt", command=encrypt_message).pack(pady=10)
tk.Button(root, text="Decrypt", command=decrypt_message).pack(pady=10)

root.mainloop()
