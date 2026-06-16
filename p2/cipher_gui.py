"""
DecodeLabs Industrial Training Kit
Project 2: Basic Encryption & Decryption - GUI Version
-------------------------------------------------------
A simple Tkinter desktop app that lets the user:
  - Type plaintext
  - Choose Caesar (numeric shift) or Vigenere (keyword)
  - Encrypt and Decrypt with one click
  - See both outputs displayed at once

Built on top of the cipher logic from caesar_cipher.py
"""

import tkinter as tk
from tkinter import messagebox

from caesar_cipher import (
    caesar_encrypt,
    caesar_decrypt,
    vigenere_encrypt,
    vigenere_decrypt,
)


class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DecodeLabs - Project 2: Encryption & Decryption")
        self.root.geometry("520x480")
        self.root.configure(bg="#eef5ee")

        # ---------- Title ----------
        title = tk.Label(
            root,
            text="Basic Encryption & Decryption",
            font=("Segoe UI", 16, "bold"),
            bg="#eef5ee",
            fg="#5a7d5a",
        )
        title.pack(pady=(15, 5))

        subtitle = tk.Label(
            root,
            text="Caesar Cipher & Vigenere Cipher",
            font=("Segoe UI", 10),
            bg="#eef5ee",
            fg="#5a7d5a",
        )
        subtitle.pack(pady=(0, 15))

        # ---------- Cipher choice ----------
        self.cipher_type = tk.StringVar(value="caesar")

        type_frame = tk.Frame(root, bg="#eef5ee")
        type_frame.pack(pady=5)

        tk.Radiobutton(
            type_frame, text="Caesar Cipher (shift number)",
            variable=self.cipher_type, value="caesar",
            bg="#eef5ee", command=self.toggle_key_label,
        ).grid(row=0, column=0, padx=10)

        tk.Radiobutton(
            type_frame, text="Vigenere Cipher (keyword)",
            variable=self.cipher_type, value="vigenere",
            bg="#eef5ee", command=self.toggle_key_label,
        ).grid(row=0, column=1, padx=10)

        # ---------- Input text ----------
        tk.Label(root, text="Enter Text:", bg="#eef5ee", anchor="w").pack(
            fill="x", padx=20, pady=(15, 0)
        )
        self.input_text = tk.Text(root, height=4, width=55, wrap="word")
        self.input_text.pack(padx=20, pady=5)

        # ---------- Key input ----------
        self.key_label = tk.Label(root, text="Shift Key (number):", bg="#eef5ee", anchor="w")
        self.key_label.pack(fill="x", padx=20, pady=(10, 0))
        self.key_entry = tk.Entry(root, width=20)
        self.key_entry.pack(padx=20, pady=5, anchor="w")

        # ---------- Buttons ----------
        button_frame = tk.Frame(root, bg="#eef5ee")
        button_frame.pack(pady=15)

        tk.Button(
            button_frame, text="Encrypt", width=12,
            bg="#7aa17a", fg="white", command=self.encrypt
        ).grid(row=0, column=0, padx=10)

        tk.Button(
            button_frame, text="Decrypt", width=12,
            bg="#7aa1c8", fg="white", command=self.decrypt
        ).grid(row=0, column=1, padx=10)

        tk.Button(
            button_frame, text="Clear", width=12,
            bg="#cccccc", command=self.clear
        ).grid(row=0, column=2, padx=10)

        # ---------- Output ----------
        tk.Label(root, text="Result:", bg="#eef5ee", anchor="w").pack(
            fill="x", padx=20, pady=(10, 0)
        )
        self.output_text = tk.Text(root, height=4, width=55, wrap="word", bg="#f7f7f7")
        self.output_text.pack(padx=20, pady=5)
        self.output_text.config(state="disabled")

    def toggle_key_label(self):
        if self.cipher_type.get() == "caesar":
            self.key_label.config(text="Shift Key (number):")
        else:
            self.key_label.config(text="Keyword (letters only):")

    def get_key(self):
        key = self.key_entry.get().strip()
        if self.cipher_type.get() == "caesar":
            try:
                return int(key)
            except ValueError:
                messagebox.showerror("Invalid Key", "Please enter a whole number for the shift key.")
                return None
        else:
            if not key.isalpha():
                messagebox.showerror("Invalid Key", "Please enter a keyword using letters only.")
                return None
            return key

    def show_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", text)
        self.output_text.config(state="disabled")

    def encrypt(self):
        text = self.input_text.get("1.0", tk.END).rstrip("\n")
        key = self.get_key()
        if key is None:
            return

        if self.cipher_type.get() == "caesar":
            result = caesar_encrypt(text, key)
        else:
            result = vigenere_encrypt(text, key)

        self.show_output(result)

    def decrypt(self):
        text = self.input_text.get("1.0", tk.END).rstrip("\n")
        key = self.get_key()
        if key is None:
            return

        if self.cipher_type.get() == "caesar":
            result = caesar_decrypt(text, key)
        else:
            result = vigenere_decrypt(text, key)

        self.show_output(result)

    def clear(self):
        self.input_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.show_output("")


if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
