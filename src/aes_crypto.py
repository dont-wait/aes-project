from Crypto.Cipher import AES
import base64
import os

class AESCrypto:
    @staticmethod
    def generate_random_key(key_size_bits):
        key_size_bytes = key_size_bits // 8
        key_bytes = os.urandom(key_size_bytes)
        print(f"DEBUG - Generated key length in bytes: {len(key_bytes)}")
        print(f"DEBUG - Key (hex): {key_bytes.hex()}")
        return key_bytes.hex()  

    @staticmethod
    def pad(data):
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        print(f"DEBUG - Original data length: {len(data)}")
        print(f"DEBUG - Padding length: {padding_length}")
        print(f"DEBUG - Padded data length: {len(padded_data)}")
        return padded_data

    @staticmethod
    def unpad(data):
        padding_length = data[-1]
        print(f"DEBUG - Data length before unpadding: {len(data)}")
        print(f"DEBUG - Detected padding length: {padding_length}")
        
        if padding_length > 16 or padding_length < 1:
            print(f"DEBUG - Invalid padding length: {padding_length}")
            raise ValueError("Invalid padding")
            
        # Kiểm tra tất cả các byte padding có giống nhau không
        if data[-padding_length:] != bytes([padding_length] * padding_length):
            print(f"DEBUG - Invalid padding values: {data[-padding_length:]}")
            raise ValueError("Invalid padding")
            
        unpadded_data = data[:-padding_length]
        print(f"DEBUG - Data length after unpadding: {len(unpadded_data)}")
        return unpadded_data

    @staticmethod
    def encrypt(plain_data, key, key_size_bits, output_format="Base64"):
        try:
            print(f"\n=== ENCRYPTION PROCESS STARTED ===")
            key_size_bytes = key_size_bits // 8
            print(f"DEBUG - Required key size: {key_size_bytes} bytes")
            
            # Xử lý key
            print(f"DEBUG - Key type: {type(key)}")
            if all(c in "0123456789ABCDEFabcdef" for c in key) and len(key) == key_size_bytes * 2:
                print(f"DEBUG - Key recognized as hex string, length: {len(key)}")
                key_bytes = bytes.fromhex(key)
            else:
                print(f"DEBUG - Key treated as UTF-8 string, length: {len(key)}")
                key_bytes = key.encode('utf-8')
                
            if len(key_bytes) != key_size_bytes:
                print(f"DEBUG - Key length mismatch: {len(key_bytes)} vs required {key_size_bytes}")
                raise ValueError(f"Secret key must be {key_size_bytes} bytes long for {key_size_bits}-bit encryption!")
            
            # Xử lý dữ liệu đầu vào
            if isinstance(plain_data, str):
                print(f"DEBUG - Input is string, length: {len(plain_data)}")
                plain_data_bytes = plain_data.encode('utf-8')
            elif isinstance(plain_data, bytes):
                print(f"DEBUG - Input is already bytes, length: {len(plain_data)}")
                plain_data_bytes = plain_data
            else:
                print(f"DEBUG - Invalid input type: {type(plain_data)}")
                raise TypeError("Input data must be string or bytes")
            
            # Tiến hành mã hóa
            print(f"DEBUG - Creating AES cipher with key length: {len(key_bytes)}")
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            print(f"DEBUG - Applying padding to data")
            padded_data = AESCrypto.pad(plain_data_bytes)
            print(f"DEBUG - Encrypting data")
            encrypted = cipher.encrypt(padded_data)
            print(f"DEBUG - Encrypted data length: {len(encrypted)}")
            
            # Định dạng đầu ra
            if output_format == "Base64":
                print(f"DEBUG - Converting to Base64")
                result = base64.b64encode(encrypted).decode('utf-8')
                print(f"DEBUG - Base64 result length: {len(result)}")
            elif output_format == "Hex":
                print(f"DEBUG - Converting to Hex")
                result = encrypted.hex().upper()
                print(f"DEBUG - Hex result length: {len(result)}")
            elif output_format == "Bytes":
                print(f"DEBUG - Returning raw bytes")
                result = encrypted
                print(f"DEBUG - Bytes result length: {len(result)}")
            else:
                print(f"DEBUG - Invalid output format: {output_format}")
                raise ValueError("Invalid output format. Use 'Base64', 'Hex', or 'Bytes'")
                
            print(f"=== ENCRYPTION PROCESS COMPLETED ===\n")
            return result
                
        except Exception as e:
            print(f"DEBUG - ENCRYPTION ERROR: {str(e)}")
            raise Exception(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt(encrypted_data, key, key_size_bits, input_format="Auto", output_format="Auto"):
        try:
            print(f"\n=== DECRYPTION PROCESS STARTED ===")
            key_size_bytes = key_size_bits // 8
            print(f"DEBUG - Required key size: {key_size_bytes} bytes")
            
            # Xử lý key
            print(f"DEBUG - Key type: {type(key)}")
            if all(c in "0123456789ABCDEFabcdef" for c in key) and len(key) == key_size_bytes * 2:
                print(f"DEBUG - Key recognized as hex string, length: {len(key)}")
                key_bytes = bytes.fromhex(key)
            else:
                print(f"DEBUG - Key treated as UTF-8 string, length: {len(key)}")
                key_bytes = key.encode('utf-8')
                
            print(f"DEBUG - Converted key length: {len(key_bytes)} bytes")
            if len(key_bytes) != key_size_bytes:
                print(f"DEBUG - Key length mismatch: {len(key_bytes)} vs required {key_size_bytes}")
                raise ValueError(f"Secret key must be {key_size_bytes} bytes long for {key_size_bits}-bit decryption!")
            
            # Xử lý dữ liệu đầu vào
            print(f"DEBUG - Input format: {input_format}")
            print(f"DEBUG - Input data type: {type(encrypted_data)}")
            
            if isinstance(encrypted_data, bytes):
                print(f"DEBUG - Input is already bytes, length: {len(encrypted_data)}")
                encrypted_bytes = encrypted_data
            elif input_format == "Base64" or (input_format == "Auto" and isinstance(encrypted_data, str)):
                try:
                    # Thử giải mã Base64
                    print(f"DEBUG - Attempting Base64 decode of length: {len(encrypted_data)}")
                    encrypted_bytes = base64.b64decode(encrypted_data)
                    print(f"DEBUG - Base64 decode successful, length: {len(encrypted_bytes)}")
                except Exception as e:
                    print(f"DEBUG - Base64 decode failed: {str(e)}")
                    if input_format == "Base64":
                        raise ValueError(f"Invalid Base64 string: {str(e)}")
                    # Nếu không phải Base64 và đang ở chế độ Auto, thử với Hex
                    print(f"DEBUG - Trying Hex decode instead")
                    if not all(c in "0123456789ABCDEFabcdef" for c in encrypted_data):
                        print(f"DEBUG - Not a valid hex string")
                        raise ValueError("Invalid data format - not Base64 or Hex")
                    encrypted_bytes = bytes.fromhex(encrypted_data)
                    print(f"DEBUG - Hex decode successful, length: {len(encrypted_bytes)}")
            elif input_format == "Hex" and isinstance(encrypted_data, str):
                if not all(c in "0123456789ABCDEFabcdef" for c in encrypted_data):
                    print(f"DEBUG - Invalid hex string")
                    raise ValueError("Invalid Hex string")
                encrypted_bytes = bytes.fromhex(encrypted_data)
                print(f"DEBUG - Hex decode successful, length: {len(encrypted_bytes)}")
            else:
                print(f"DEBUG - Invalid input type/format combination")
                raise TypeError("Input must be bytes or string (Base64/Hex)")
            
            # Kiểm tra độ dài dữ liệu mã hóa
            if len(encrypted_bytes) % 16 != 0:
                print(f"DEBUG - Invalid encrypted data length: {len(encrypted_bytes)}")
                raise ValueError("Decryption failed: Data must be multiple of 16 bytes")
                
            # Tiến hành giải mã
            print(f"DEBUG - Creating AES cipher with key length: {len(key_bytes)}")
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            print(f"DEBUG - Decrypting data")
            decrypted = cipher.decrypt(encrypted_bytes)
            print(f"DEBUG - Decrypted data length (before unpadding): {len(decrypted)}")
            unpadded_data = AESCrypto.unpad(decrypted)
            print(f"DEBUG - Unpadded data length: {len(unpadded_data)}")
            
            # Định dạng đầu ra
            print(f"DEBUG - Output format: {output_format}")
            if output_format == "Bytes":
                print(f"DEBUG - Returning raw bytes")
                result = unpadded_data
            elif output_format == "Base64":
                print(f"DEBUG - Converting to Base64")
                result = base64.b64encode(unpadded_data).decode('utf-8')
                print(f"DEBUG - Base64 result length: {len(result)}")
            elif output_format == "Auto" or output_format == "Plain-Text":
                # Thử decode UTF-8, nếu lỗi thì trả về bytes
                try:
                    print(f"DEBUG - Attempting UTF-8 decode")
                    result = unpadded_data.decode('utf-8')
                    print(f"DEBUG - UTF-8 decode successful, text length: {len(result)}")
                except UnicodeDecodeError as e:
                    print(f"DEBUG - UTF-8 decode failed: {str(e)}")
                    # Nếu không thể decode UTF-8, trả về dạng bytes hoặc base64
                    if output_format == "Auto":
                        print(f"DEBUG - Falling back to bytes")
                        result = unpadded_data  # Trả về bytes
                    else:
                        print(f"DEBUG - Falling back to Base64")
                        result = base64.b64encode(unpadded_data).decode('utf-8')  # Chuyển sang Base64
                        print(f"DEBUG - Base64 result length: {len(result)}")
            else:
                print(f"DEBUG - Invalid output format: {output_format}")
                raise ValueError("Invalid output format. Use 'Auto', 'Plain-Text', 'Base64', or 'Bytes'")
                
            print(f"=== DECRYPTION PROCESS COMPLETED ===\n")
            return result
                
        except Exception as e:
            print(f"DEBUG - DECRYPTION ERROR: {str(e)}")
            raise Exception(f"Decryption failed: {str(e)}")