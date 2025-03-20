import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Kích thước khối của AES (luôn là 16 bytes)
BLOCK_SIZE = 16

def encrypt_file(input_file, output_file, key, mode=AES.MODE_CBC, chunk_size=64*1024):
    """
    Mã hóa file bằng AES.
    
    Args:
        input_file (str): Đường dẫn file cần mã hóa.
        output_file (str): Đường dẫn file đầu ra.
        key (bytes): Khóa mã hóa (16, 24, hoặc 32 bytes).
        mode (int): Chế độ AES (mặc định là CBC).
        chunk_size (int): Kích thước mỗi lần đọc (mặc định 64KB).
    
    Returns:
        None
    
    Raises:
        ValueError: Nếu khóa không hợp lệ.
        FileNotFoundError: Nếu file đầu vào không tồn tại.
    """
    # Kiểm tra khóa có hợp lệ không
    if len(key) not in (16, 24, 32):
        raise ValueError("Khóa phải dài 16, 24, hoặc 32 bytes!")

    # Kiểm tra file đầu vào có tồn tại không
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Không tìm thấy file: {input_file}")

    # Tạo cipher với khóa và chế độ
    cipher = AES.new(key, mode)
    
    # Lấy IV (nếu chế độ cần IV, như CBC)
    iv = cipher.iv if mode == AES.MODE_CBC else b''

    # Mở file để đọc và ghi
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Ghi IV vào đầu file (nếu có)
        if iv:
            outfile.write(iv)

        # Đọc và mã hóa từng phần của file
        while True:
            chunk = infile.read(chunk_size)  # Đọc một phần file
            if not chunk:  # Nếu hết file thì dừng
                break
            # Nếu phần cuối không đủ kích thước khối, thêm đệm
            if len(chunk) % BLOCK_SIZE != 0:
                chunk = pad(chunk, BLOCK_SIZE)
            # Mã hóa và ghi vào file đầu ra
            encrypted_chunk = cipher.encrypt(chunk)
            outfile.write(encrypted_chunk)

def decrypt_file(input_file, output_file, key, mode=AES.MODE_CBC, chunk_size=64*1024):
    """
    Giải mã file đã mã hóa bằng AES.
    
    Args:
        input_file (str): Đường dẫn file đã mã hóa.
        output_file (str): Đường dẫn file đầu ra.
        key (bytes): Khóa giải mã (phải khớp với khóa mã hóa).
        mode (int): Chế độ AES (mặc định là CBC).
        chunk_size (int): Kích thước mỗi lần đọc (mặc định 64KB).
    
    Returns:
        None
    
    Raises:
        ValueError: Nếu khóa hoặc file không hợp lệ.
        FileNotFoundError: Nếu file đầu vào không tồn tại.
    """
    # Kiểm tra khóa có hợp lệ không
    if len(key) not in (16, 24, 32):
        raise ValueError("Khóa phải dài 16, 24, hoặc 32 bytes!")

    # Kiểm tra file đầu vào có tồn tại không
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Không tìm thấy file: {input_file}")

    # Mở file để đọc
    with open(input_file, 'rb') as infile:
        # Đọc IV nếu chế độ là CBC
        iv = infile.read(16) if mode == AES.MODE_CBC else b''
        if mode == AES.MODE_CBC and len(iv) != 16:
            raise ValueError("File không có IV hợp lệ (cần 16 bytes cho CBC)!")

        # Tạo cipher với khóa và IV (nếu có)
        cipher = AES.new(key, mode, iv=iv) if iv else AES.new(key, mode)

        # Mở file đầu ra để ghi
        with open(output_file, 'wb') as outfile:
            # Đọc và giải mã từng phần
            while True:
                chunk = infile.read(chunk_size)  # Đọc một phần file
                if not chunk:  # Nếu hết file thì dừng
                    break
                # Giải mã phần dữ liệu
                decrypted_chunk = cipher.decrypt(chunk)
                # Nếu là phần cuối, bỏ đệm
                if not infile.peek(1):  # Kiểm tra xem có dữ liệu tiếp theo không
                    decrypted_chunk = unpad(decrypted_chunk, BLOCK_SIZE)
                # Ghi vào file đầu ra
                outfile.write(decrypted_chunk)

def generate_key(length=16):
    """
    Tạo khóa ngẫu nhiên cho AES.
    
    Args:
        length (int): Độ dài khóa (16, 24, hoặc 32 bytes, mặc định là 16).
    
    Returns:
        bytes: Khóa ngẫu nhiên.
    
    Raises:
        ValueError: Nếu độ dài khóa không hợp lệ.
    """
    if length not in (16, 24, 32):
        raise ValueError("Độ dài khóa phải là 16, 24, hoặc 32 bytes!")
    return get_random_bytes(length)