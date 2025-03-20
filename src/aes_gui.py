import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import pyperclip  
from aes_logic import encrypt_file, decrypt_file, generate_key

def create_gui():
    window = tk.Tk()
    window.title("AES Encryption Tool")
    window.geometry("700x600")  
    window.configure(bg="#e6f0fa")
    window.resizable(False, False)

    # Căn giữa màn hình
    screen_width = window.winfo_screenwidth()  # Lấy chiều rộng màn hình
    screen_height = window.winfo_screenheight()  # Lấy chiều cao màn hình
    window_width = 700  # Chiều rộng cửa sổ
    window_height = 600  # Chiều cao cửa sổ
    x = (screen_width // 2) - (window_width // 2)  # Tọa độ x để căn giữa
    y = (screen_height // 2) - (window_height // 2)  # Tọa độ y để căn giữa
    window.geometry(f"{window_width}x{window_height}+{x}+{y}")  # Đặt vị trí cửa sổ


    # Cấu hình style
    style = ttk.Style()
    style.configure("TButton", font=("Arial", 10, "bold"), padding=10)
    style.configure("TLabel", font=("Arial", 11), background="#e6f0fa")

    # Tiêu đề
    title_label = ttk.Label(window, text="Công cụ mã hóa AES", font=("Arial", 16, "bold"))
    title_label.pack(pady=10)

    # Frame tìm kiếm (trên cùng)
    search_frame = tk.Frame(window, bg="#ffffff", bd=2, relief="ridge")
    search_frame.pack(padx=20, pady=5, fill="x")
    ttk.Label(search_frame, text="Tìm trong thư mục:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    dir_entry = ttk.Entry(search_frame, width=40)
    dir_entry.grid(row=0, column=1, padx=5, pady=5)
    dir_entry.insert(0, os.getcwd())
    ttk.Button(search_frame, text="Chọn", command=lambda: select_directory(dir_entry)).grid(row=0, column=2, padx=5, pady=5)
    
    ttk.Label(search_frame, text="Từ khóa:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    search_entry = ttk.Entry(search_frame, width=40)
    search_entry.grid(row=1, column=1, padx=5, pady=5)
    ttk.Button(search_frame, text="Tìm", 
               command=lambda: search_files(dir_entry, search_entry, results_listbox)).grid(row=1, column=2, padx=5, pady=5)

    # Frame kết quả tìm kiếm
    result_frame = tk.Frame(window, bg="#ffffff", bd=2, relief="ridge")
    result_frame.pack(padx=20, pady=5, fill="both", expand=True)
    scrollbar = ttk.Scrollbar(result_frame, orient="vertical")
    scrollbar.pack(side="right", fill="y")
    results_listbox = tk.Listbox(result_frame, width=80, height=8, yscrollcommand=scrollbar.set)
    results_listbox.pack(padx=5, pady=5, fill="both", expand=True)
    scrollbar.config(command=results_listbox.yview)
    results_listbox.bind("<Double-1>", lambda event: select_file_from_list(results_listbox, file_entry))

    # Frame xử lý file
    main_frame = tk.Frame(window, bg="#ffffff", bd=2, relief="ridge")
    main_frame.pack(padx=20, pady=5, fill="x")

    ttk.Label(main_frame, text="File cần xử lý:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
    file_entry = ttk.Entry(main_frame, width=40)
    file_entry.grid(row=0, column=1, padx=10, pady=5)
    ttk.Button(main_frame, text="Browse", command=lambda: browse_file(file_entry)).grid(row=0, column=2, padx=10, pady=5)

    ttk.Label(main_frame, text="Kích thước khóa:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
    key_size_var = tk.StringVar(value="128")
    key_size_menu = ttk.Combobox(main_frame, textvariable=key_size_var, values=["128", "192", "256"], state="readonly", width=10)
    key_size_menu.grid(row=1, column=1, padx=10, pady=5, sticky="w")
    ttk.Button(main_frame, text="Tạo khóa", command=lambda: generate_random_key(key_size_var, key_entry)).grid(row=1, column=2, padx=10, pady=5)

    ttk.Label(main_frame, text="Khóa (hex):").grid(row=2, column=0, padx=10, pady=5, sticky="e")
    key_entry = ttk.Entry(main_frame, width=40, show="*")
    key_entry.grid(row=2, column=1, padx=10, pady=5)
    show_key_btn = ttk.Button(main_frame, text="Hiện", command=lambda: toggle_key_visibility(key_entry, show_key_btn))
    show_key_btn.grid(row=2, column=2, padx=10, pady=5)

    # Frame nút chức năng
    button_frame = tk.Frame(main_frame, bg="#ffffff")
    button_frame.grid(row=3, column=0, columnspan=3, pady=10)
    ttk.Button(button_frame, text="Mã hóa", command=lambda: encrypt(file_entry, key_entry, key_size_var)).pack(side="left", padx=10)
    ttk.Button(button_frame, text="Giải mã", command=lambda: decrypt(file_entry, key_entry, key_size_var)).pack(side="left", padx=10)
    ttk.Button(button_frame, text="Thoát", command=window.quit).pack(side="left", padx=10)

    # Nhãn trạng thái
    status_label = ttk.Label(window, text="Trạng thái: Sẵn sàng", foreground="green")
    status_label.pack(pady=5)

    # Hàm hỗ trợ
    def update_status(message, color):
        status_label.config(text=f"Trạng thái: {message}", foreground=color)

    def show_error(message):
        messagebox.showerror("Lỗi", message)

    def select_directory(entry):
        dir_path = filedialog.askdirectory()
        if dir_path:
            entry.delete(0, tk.END)
            entry.insert(0, dir_path)
            update_status("Đã chọn thư mục", "blue")

    def search_files(dir_entry, search_entry, listbox):
        directory, term = dir_entry.get(), search_entry.get().strip().lower()
        if not os.path.isdir(directory):
            show_error("Thư mục không hợp lệ!")
            return
        if not term:
            show_error("Nhập từ khóa tìm kiếm!")
            return
        listbox.delete(0, tk.END)
        found = False
        for root, _, files in os.walk(directory):
            for file in [f for f in files if term in f.lower()]:
                listbox.insert(tk.END, os.path.join(root, file))
                found = True
        update_status("Đã tìm thấy file" if found else "Không tìm thấy file", "blue" if found else "red")

    def select_file_from_list(listbox, entry):
        if listbox.curselection():
            file_path = listbox.get(listbox.curselection()[0])
            entry.delete(0, tk.END)
            entry.insert(0, file_path)
            listbox.delete(0, tk.END)
            update_status("Đã chọn file", "blue")

    def browse_file(entry):
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if file_path:
            entry.delete(0, tk.END)
            entry.insert(0, file_path)
            update_status("Đã chọn file", "blue")

    def generate_random_key(size_var, entry):
        size = int(size_var.get()) // 8
        key = generate_key(size)
        entry.delete(0, tk.END)
        entry.insert(0, key.hex())
        update_status(f"Đã tạo khóa ({size_var.get()} bit)", "blue")

    def toggle_key_visibility(entry, button):
        if entry.cget("show") == "*":
            entry.config(show="")
            button.config(text="Ẩn")
            pyperclip.copy(entry.get())  # Sao chép khóa vào clipboard
            update_status("Đã sao chép khóa vào clipboard", "blue")
        else:
            entry.config(show="*")
            button.config(text="Hiện")

    def validate_key(key_hex, size):
        return len(key_hex) == size * 2 and all(c in "0123456789abcdefABCDEF" for c in key_hex)

    def encrypt(file_entry, key_entry, size_var):
        input_file, key_hex = file_entry.get(), key_entry.get().strip()
        size = int(size_var.get()) // 8
        if not input_file:
            show_error("Chọn file trước!")
            return
        if not validate_key(key_hex, size):
            show_error(f"Khóa phải là hex {size * 2} ký tự!")
            return
        key = bytes.fromhex(key_hex)
        output_file = "encrypted_" + os.path.basename(input_file)
        try:
            encrypt_file(input_file, output_file, key)
            update_status(f"Đã mã hóa: {output_file}", "green")
            messagebox.showinfo("Thành công", f"File đã mã hóa: {output_file}")
        except Exception as e:
            update_status("Lỗi mã hóa", "red")
            show_error(f"Lỗi: {str(e)}")

    def decrypt(file_entry, key_entry, size_var):
        input_file, key_hex = file_entry.get(), key_entry.get().strip()
        size = int(size_var.get()) // 8
        if not input_file:
            show_error("Chọn file trước!")
            return
        if not validate_key(key_hex, size):
            show_error(f"Khóa phải là hex {size * 2} ký tự!")
            return
        key = bytes.fromhex(key_hex)
        output_file = "decrypted_" + os.path.basename(input_file)
        try:
            decrypt_file(input_file, output_file, key)
            update_status(f"Đã giải mã: {output_file}", "green")
            messagebox.showinfo("Thành công", f"File đã giải mã: {output_file}")
        except Exception as e:
            update_status("Lỗi giải mã", "red")
            show_error(f"Lỗi: {str(e)}")


    return window


def add_tooltip(widget, text):
    tooltip = tk.Toplevel(widget)
    tooltip.wm_overrideredirect(True)
    tooltip.wm_geometry("+1000+1000")  # Ẩn ban đầu
    label = tk.Label(tooltip, text=text, background="yellow", relief="solid", borderwidth=1)
    label.pack()

    def enter(event):
        x, y = widget.winfo_rootx() + 20, widget.winfo_rooty() + 20
        tooltip.wm_geometry(f"+{x}+{y}")
        tooltip.deiconify()

    def leave(event):
        tooltip.withdraw()

    widget.bind("<Enter>", enter)
    widget.bind("<Leave>", leave)
    tooltip.withdraw()

tk.Widget.create_tool_tip = add_tooltip