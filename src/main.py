import tkinter as tk
from aes_gui import AESApp

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)

    # Căn giữa cửa sổ
    window_width = 800
    window_height = 600

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    x_position = (screen_width - window_width) // 2
    y_position = (screen_height - window_height) // 2

    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

    root.resizable(False, False)

    root.mainloop()