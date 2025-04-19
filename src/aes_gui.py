import tkinter as tk
from tkinter import ttk, messagebox
from aes_crypto import AESCrypto

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")

        # Căn giữa cửa sổ
        self.root.geometry("1150x600")
        self.root.resizable(False, False)

        # Khung chính
        self.main_frame = tk.Frame(self.root, padx=20, pady=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # LabelFrame cho mã hóa
        self.enc_frame = tk.LabelFrame(self.main_frame, text="🔐 AES Encryption", padx=10, pady=10, font=("Arial", 12, "bold"))
        self.enc_frame.grid(row=0, column=0, padx=10, pady=10, sticky="n")

        # LabelFrame cho giải mã
        self.dec_frame = tk.LabelFrame(self.main_frame, text="🔓 AES Decryption", padx=10, pady=10, font=("Arial", 12, "bold"))
        self.dec_frame.grid(row=0, column=1, padx=10, pady=10, sticky="n")

        self.build_encryption_section()
        self.build_decryption_section()

    def build_encryption_section(self):
        # Plain Text Input
        tk.Label(self.enc_frame, text="Enter Plain Text:").grid(row=0, column=0, sticky="w")
        self.plain_text = tk.Text(self.enc_frame, height=3, width=45)
        self.plain_text.grid(row=1, column=0, columnspan=2, pady=5)

        # Key Size
        tk.Label(self.enc_frame, text="Key Size (bits):").grid(row=2, column=0, sticky="w")
        self.key_size_enc = ttk.Combobox(self.enc_frame, values=["128", "192", "256"], state="readonly", width=10)
        self.key_size_enc.set("128")
        self.key_size_enc.grid(row=2, column=1, sticky="w")

        # Secret Key
        tk.Label(self.enc_frame, text="Secret Key:").grid(row=3, column=0, sticky="w")
        self.secret_key_enc = tk.Entry(self.enc_frame, width=45)
        self.secret_key_enc.grid(row=4, column=0, columnspan=2, pady=5)

        # Random Key Button
        tk.Button(self.enc_frame, text="🔄 Random Key", command=self.generate_random_key_enc).grid(row=5, column=0, columnspan=2, pady=5)

        # Output Format
        tk.Label(self.enc_frame, text="Output Format:").grid(row=6, column=0, sticky="w")
        self.output_format_enc = tk.StringVar(value="Base64")
        format_frame = tk.Frame(self.enc_frame)
        format_frame.grid(row=6, column=1, sticky="w")
        tk.Radiobutton(format_frame, text="Base64", variable=self.output_format_enc, value="Base64").pack(side=tk.LEFT)
        tk.Radiobutton(format_frame, text="Hex", variable=self.output_format_enc, value="Hex").pack(side=tk.LEFT)

        # Encrypt Button
        tk.Button(self.enc_frame, text="Encrypt", command=self.encrypt, bg="#4CAF50", fg="white", width=20).grid(row=7, column=0, columnspan=2, pady=10)

        # Output
        tk.Label(self.enc_frame, text="Encrypted Output:").grid(row=8, column=0, sticky="w")
        self.encrypted_output = tk.Text(self.enc_frame, height=3, width=45)
        self.encrypted_output.grid(row=9, column=0, columnspan=2, pady=5)

    def build_decryption_section(self):
        # Encrypted Text Input
        tk.Label(self.dec_frame, text="Encrypted Text:").grid(row=0, column=0, sticky="w")
        self.encrypted_text = tk.Text(self.dec_frame, height=3, width=45)
        self.encrypted_text.grid(row=1, column=0, columnspan=2, pady=5)

        # Key Size
        tk.Label(self.dec_frame, text="Key Size (bits):").grid(row=2, column=0, sticky="w")
        self.key_size_dec = ttk.Combobox(self.dec_frame, values=["128", "192", "256"], state="readonly", width=10)
        self.key_size_dec.set("128")
        self.key_size_dec.grid(row=2, column=1, sticky="w")

        # Secret Key
        tk.Label(self.dec_frame, text="Secret Key:").grid(row=3, column=0, sticky="w")
        self.secret_key_dec = tk.Entry(self.dec_frame, width=45)
        self.secret_key_dec.grid(row=4, column=0, columnspan=2, pady=5)

        # Random Key Button
        tk.Button(self.dec_frame, text="🔄 Random Key", command=self.generate_random_key_dec).grid(row=5, column=0, columnspan=2, pady=5)

        # Output Format
        tk.Label(self.dec_frame, text="Output Format:").grid(row=6, column=0, sticky="w")
        self.output_format_dec = tk.StringVar(value="Plain-Text")
        format_frame = tk.Frame(self.dec_frame)
        format_frame.grid(row=6, column=1, sticky="w")
        tk.Radiobutton(format_frame, text="Plain-Text", variable=self.output_format_dec, value="Plain-Text").pack(side=tk.LEFT)
        tk.Radiobutton(format_frame, text="Base64", variable=self.output_format_dec, value="Base64").pack(side=tk.LEFT)

        # Decrypt Button
        tk.Button(self.dec_frame, text="Decrypt", command=self.decrypt, bg="#2196F3", fg="white", width=20).grid(row=7, column=0, columnspan=2, pady=10)

        # Output
        tk.Label(self.dec_frame, text="Decrypted Output:").grid(row=8, column=0, sticky="w")
        self.decrypted_output = tk.Text(self.dec_frame, height=3, width=45)
        self.decrypted_output.grid(row=9, column=0, columnspan=2, pady=5)

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
            plain_text = self.plain_text.get("1.0", tk.END).strip()
            key = self.secret_key_enc.get()
            key_size = int(self.key_size_enc.get())
            output_format = self.output_format_enc.get()

            encrypted_output = AESCrypto.encrypt(plain_text, key, key_size, output_format)
            self.encrypted_output.delete("1.0", tk.END)
            self.encrypted_output.insert(tk.END, encrypted_output)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        try:
            encrypted_text = self.encrypted_text.get("1.0", tk.END).strip()
            key = self.secret_key_dec.get()
            key_size = int(self.key_size_dec.get())
            output_format = self.output_format_dec.get()

            decrypted_output = AESCrypto.decrypt(encrypted_text, key, key_size, output_format)
            self.decrypted_output.delete("1.0", tk.END)
            self.decrypted_output.insert(tk.END, decrypted_output)

        except Exception as e:
            messagebox.showerror("Error", str(e))