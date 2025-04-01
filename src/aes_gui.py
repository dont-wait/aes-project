import tkinter as tk
from tkinter import ttk, messagebox
from aes_crypto import AESCrypto

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")

        # Frame chính
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(padx=10, pady=10)

        # Chia giao diện thành 2 phần: Encryption và Decryption
        self.enc_frame = tk.Frame(self.main_frame)
        self.enc_frame.grid(row=0, column=0, padx=10)

        self.dec_frame = tk.Frame(self.main_frame)
        self.dec_frame.grid(row=0, column=1, padx=10)

        # --- Encryption Section ---
        tk.Label(self.enc_frame, text="AES Encryption", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=5)

        # Plain Text Input
        tk.Label(self.enc_frame, text="Enter Plain Text to Encrypt").grid(row=1, column=0, sticky="w")
        self.plain_text = tk.Text(self.enc_frame, height=3, width=40)
        self.plain_text.grid(row=2, column=0, columnspan=2, pady=5)

        # Key Size
        tk.Label(self.enc_frame, text="Key Size in Bits").grid(row=3, column=0, sticky="w")
        self.key_size_enc = ttk.Combobox(self.enc_frame, values=["128", "192", "256"], state="readonly")
        self.key_size_enc.set("128")
        self.key_size_enc.grid(row=4, column=0, pady=5)

        # Secret Key
        tk.Label(self.enc_frame, text="Enter Secret Key").grid(row=5, column=0, sticky="w")
        self.secret_key_enc = tk.Entry(self.enc_frame, width=40)
        self.secret_key_enc.grid(row=6, column=0, columnspan=2, pady=5)

        # Random Key Button for Encryption
        tk.Button(self.enc_frame, text="Random Key", command=self.generate_random_key_enc).grid(row=7, column=0, columnspan=2, pady=5)

        # Output Format
        tk.Label(self.enc_frame, text="Output Text Format").grid(row=8, column=0, sticky="w")
        self.output_format_enc = tk.StringVar(value="Base64")
        tk.Radiobutton(self.enc_frame, text="Base64", variable=self.output_format_enc, value="Base64").grid(row=9, column=0, sticky="w")
        tk.Radiobutton(self.enc_frame, text="Hex", variable=self.output_format_enc, value="Hex").grid(row=9, column=1, sticky="w")

        # Encrypt Button
        tk.Button(self.enc_frame, text="Encrypt", command=self.encrypt).grid(row=10, column=0, columnspan=2, pady=10)

        # Encrypted Output
        tk.Label(self.enc_frame, text="AES Encrypted Output").grid(row=11, column=0, sticky="w")
        self.encrypted_output = tk.Text(self.enc_frame, height=3, width=40)
        self.encrypted_output.grid(row=12, column=0, columnspan=2, pady=5)

        # --- Decryption Section ---
        tk.Label(self.dec_frame, text="AES Decryption", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=5)

        # Encrypted Text Input
        tk.Label(self.dec_frame, text="AES Encrypted Text").grid(row=1, column=0, sticky="w")
        self.encrypted_text = tk.Text(self.dec_frame, height=3, width=40)
        self.encrypted_text.grid(row=2, column=0, columnspan=2, pady=5)

        # Key Size
        tk.Label(self.dec_frame, text="Key Size in Bits").grid(row=3, column=0, sticky="w")
        self.key_size_dec = ttk.Combobox(self.dec_frame, values=["128", "192", "256"], state="readonly")
        self.key_size_dec.set("128")
        self.key_size_dec.grid(row=4, column=0, pady=5)

        # Secret Key
        tk.Label(self.dec_frame, text="Enter Secret Key used for Encryption").grid(row=5, column=0, sticky="w")
        self.secret_key_dec = tk.Entry(self.dec_frame, width=40)
        self.secret_key_dec.grid(row=6, column=0, columnspan=2, pady=5)

        # Random Key Button for Decryption
        tk.Button(self.dec_frame, text="Random Key", command=self.generate_random_key_dec).grid(row=7, column=0, columnspan=2, pady=5)

        # Output Format
        tk.Label(self.dec_frame, text="Output Text Format").grid(row=8, column=0, sticky="w")
        self.output_format_dec = tk.StringVar(value="Plain-Text")
        tk.Radiobutton(self.dec_frame, text="Plain-Text", variable=self.output_format_dec, value="Plain-Text").grid(row=9, column=0, sticky="w")
        tk.Radiobutton(self.dec_frame, text="Base64", variable=self.output_format_dec, value="Base64").grid(row=9, column=1, sticky="w")

        # Decrypt Button
        tk.Button(self.dec_frame, text="Decrypt", command=self.decrypt).grid(row=10, column=0, columnspan=2, pady=10)

        # Decrypted Output
        tk.Label(self.dec_frame, text="AES Decrypted Output").grid(row=11, column=0, sticky="w")
        self.decrypted_output = tk.Text(self.dec_frame, height=3, width=40)
        self.decrypted_output.grid(row=12, column=0, columnspan=2, pady=5)

    def generate_random_key_enc(self):
        try:
            key_size = int(self.key_size_enc.get())
            random_key = AESCrypto.generate_random_key(key_size)
            self.secret_key_enc.delete(0, tk.END)
            self.secret_key_enc.insert(0, random_key)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate random key: {str(e)}")

    def generate_random_key_dec(self):
        try:
            key_size = int(self.key_size_dec.get())
            random_key = AESCrypto.generate_random_key(key_size)
            self.secret_key_dec.delete(0, tk.END)
            self.secret_key_dec.insert(0, random_key)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate random key: {str(e)}")

    def encrypt(self):
        try:
            # Lấy dữ liệu từ giao diện
            plain_text = self.plain_text.get("1.0", tk.END).strip()
            key = self.secret_key_enc.get()
            key_size = int(self.key_size_enc.get())
            output_format = self.output_format_enc.get()

            # Gọi hàm mã hóa từ AESCrypto
            encrypted_output = AESCrypto.encrypt(plain_text, key, key_size, output_format)

            # Hiển thị kết quả
            self.encrypted_output.delete("1.0", tk.END)
            self.encrypted_output.insert(tk.END, encrypted_output)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        try:
            # Lấy dữ liệu từ giao diện
            encrypted_text = self.encrypted_text.get("1.0", tk.END).strip()
            key = self.secret_key_dec.get()
            key_size = int(self.key_size_dec.get())
            output_format = self.output_format_dec.get()

            # Gọi hàm giải mã từ AESCrypto
            decrypted_output = AESCrypto.decrypt(encrypted_text, key, key_size, output_format)

            # Hiển thị kết quả
            self.decrypted_output.delete("1.0", tk.END)
            self.decrypted_output.insert(tk.END, decrypted_output)

        except Exception as e:
            messagebox.showerror("Error", str(e))