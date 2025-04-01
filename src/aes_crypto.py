from Crypto.Cipher import AES
import base64
import os

class AESCrypto:
    # Hàm tạo khóa ngẫu nhiên dựa trên độ dài khóa (bit)
    @staticmethod
    def generate_random_key(key_size_bits):
        # Chuyển đổi độ dài khóa từ bit sang byte (1 byte = 8 bit)
        key_size_bytes = key_size_bits // 8
        # Tạo khóa ngẫu nhiên bằng os.urandom
        return os.urandom(key_size_bytes).hex()[:key_size_bytes]

    @staticmethod
    def encrypt(plain_text, key, key_size_bits, output_format="Base64"):
        try:
            # Chuyển đổi độ dài khóa từ bit sang byte
            key_size_bytes = key_size_bits // 8
            # Kiểm tra độ dài khóa
            if len(key) != key_size_bytes:
                raise ValueError(f"Secret key must be {key_size_bytes} characters long for {key_size_bits}-bit encryption!")

            # Tạo đối tượng AES với chế độ ECB
            cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)

            # Đầu vào có thể là bất kỳ chuỗi nào, mã hóa thành bytes
            plain_text_bytes = plain_text.encode('utf-8')

            # Thêm padding nếu cần (dữ liệu phải là bội của 16 byte)
            padding_length = 16 - (len(plain_text_bytes) % 16)
            plain_text_bytes += bytes([padding_length] * padding_length)

            # Mã hóa
            encrypted = cipher.encrypt(plain_text_bytes)

            # Định dạng đầu ra
            if output_format == "Base64":
                encrypted_output = base64.b64encode(encrypted).decode('utf-8')
            else:  # Hex
                encrypted_output = encrypted.hex().upper()

            return encrypted_output

        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt(encrypted_text, key, key_size_bits, output_format="Plain-Text"):
        try:
            # Chuyển đổi độ dài khóa từ bit sang byte
            key_size_bytes = key_size_bits // 8
            # Kiểm tra độ dài khóa
            if len(key) != key_size_bytes:
                raise ValueError(f"Secret key must be {key_size_bytes} characters long for {key_size_bits}-bit decryption!")

            # Đầu vào có thể là bất kỳ chuỗi nào, thử giải mã dưới dạng Base64 hoặc Hex
            try:
                # Thử giải mã Base64
                encrypted_data = base64.b64decode(encrypted_text)
            except:
                try:
                    # Nếu không phải Base64, thử Hex
                    encrypted_data = bytes.fromhex(encrypted_text)
                except:
                    # Nếu cả hai đều thất bại, coi như chuỗi thô và thử giải mã trực tiếp
                    encrypted_data = encrypted_text.encode('utf-8')

            # Kiểm tra xem dữ liệu có đúng kích thước block (16 bytes) không
            if len(encrypted_data) % 16 != 0:
                raise ValueError("Decryption failed: Data must be aligned to block boundary in ECB mode (multiple of 16 bytes).")

            # Tạo đối tượng AES với chế độ ECB
            cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)

            # Giải mã dữ liệu
            decrypted = cipher.decrypt(encrypted_data)

            # Xóa padding
            padding_length = decrypted[-1]
            if padding_length < 1 or padding_length > 16:
                raise ValueError("Invalid padding length during decryption.")
            decrypted = decrypted[:-padding_length]

            # Định dạng đầu ra
            if output_format == "Plain-Text":
                decrypted_output = decrypted.decode('utf-8')
            else:  # Base64
                decrypted_output = base64.b64encode(decrypted).decode('utf-8')

            return decrypted_output

        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")