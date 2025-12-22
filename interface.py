from encrypt import *
import tkinter as tk
from tkinter import messagebox, simpledialog
from encrypt import *

class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Message Encryption")
        self.geometry("420x400")
        self.resizable(False, False)

        tk.Label(
            self,
            text="Simple Message Encryption",
            font=("Helvetica", 16, "bold")
        ).pack(pady=15)

        self.make_button("Generate ed25519 keypair", self.gen_ed25519)
        self.make_button("Generate x25519 keypair", self.gen_x25519)
        self.make_button("Derive shared secret", self.derive_secret)
        self.make_button("Encrypt message", self.encrypt_message)
        self.make_button("Decrypt message", self.decrypt_message)
        self.make_button("Exit", self.destroy)

    def make_button(self, text, command):
        tk.Button(
            self,
            text=text,
            width=35,
            pady=5,
            command=command
        ).pack(pady=4)

    # ---- Actions ----

    def gen_ed25519(self):
        try:
            name = simpledialog.askstring("ed25519", "Enter key name:")
            if not name:
                return
            generate_ed25519_keypair(name)
            messagebox.showinfo("Success", "ed25519 keypair generated ✅")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def gen_x25519(self):
        try:
            name = simpledialog.askstring("x25519", "Enter key name:")
            if not name:
                return
            generate_x25519_keypair(name)
            messagebox.showinfo("Success", "x25519 keypair generated ✅")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def derive_secret(self):
        try:
            name = simpledialog.askstring("Shared secret", "Name for shared key:")
            peer = simpledialog.askstring("Peer key", "Peer x25519 public key name:")
            if not name or not peer:
                return

            peer_pub = load_x25519(peer)["public"]
            if peer_pub is None:
                raise ValueError("Peer public key not found")

            derive_shared_secret(name, peer_pub)
            messagebox.showinfo("Success", "Shared secret derived ✅")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_message(self):
        try:
            msg_name = simpledialog.askstring("Encrypt", "Encrypted message name:")
            key_name = simpledialog.askstring("Encrypt", "AES shared key name:")
            message = simpledialog.askstring("Encrypt", "Message to encrypt:")

            if not msg_name or not key_name or not message:
                return

            key = load_aes_shared_key(key_name)

            encrypt(
                name=msg_name,
                key=key,
                plaintext=message.encode("utf-8"),
            )

            messagebox.showinfo("Success", "Message encrypted ✅")
        except Exception as e:
            messagebox.showerror("Encryption failed", str(e))

    def decrypt_message(self):
        try:
            key_name = simpledialog.askstring("Decrypt", "AES key name:")
            if not key_name:
                return

            key = load_aes_shared_key(key_name)
            decrypt(key)

            messagebox.showinfo(
                "Success",
                "Message decrypted ✅\nSaved to decrypted_messages/"
            )
        except Exception as e:
            messagebox.showerror("Decryption failed", str(e))


app = CryptoApp()
app.mainloop()