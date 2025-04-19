from Crypto.Cipher import AES
import base64
import os

class AESCrypto:
    @staticmethod
    def generate_random_key(key_size_bits):
        key_size_bytes = key_size_bits // 8
        return os.urandom(key_size_bytes).hex()[:key_size_bytes]

    @staticmethod
    def pad(data):
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)

    @staticmethod
    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    @staticmethod
    def encrypt(plain_text, key, key_size_bits, output_format="Base64"):
        try:
            key_size_bytes = key_size_bits // 8
            key_bytes = key.encode('utf-8')
            if len(key_bytes) != key_size_bytes:
                raise ValueError(f"Secret key must be {key_size_bytes} bytes long for {key_size_bits}-bit encryption!")
            
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            plain_text_bytes = plain_text.encode('utf-8')
            padded_data = AESCrypto.pad(plain_text_bytes)
            encrypted = cipher.encrypt(padded_data)
            
            if output_format == "Base64":
                return base64.b64encode(encrypted).decode('utf-8')
            
            else:
                return encrypted.hex().upper()
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt(encrypted_text, key, key_size_bits, output_format="Plain-Text"):
        try:
            key_size_bytes = key_size_bits // 8
            key_bytes = key.encode('utf-8')
            if len(key_bytes) != key_size_bytes:
                raise ValueError(f"Secret key must be {key_size_bytes} bytes long for {key_size_bits}-bit decryption!")
            
            try:
                encrypted_data = base64.b64decode(encrypted_text)
            except:
                if not all(c in "0123456789ABCDEFabcdef" for c in encrypted_text):
                    raise ValueError("Invalid Hex string.")
                encrypted_data = bytes.fromhex(encrypted_text)
            
            if len(encrypted_data) % 16 != 0:
                raise ValueError("Decryption failed: Data must be multiple of 16 bytes.")
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted_data)
            unpadded_data = AESCrypto.unpad(decrypted)
            
            if output_format == "Plain-Text":
                return unpadded_data.decode('utf-8')
            else:
                return base64.b64encode(unpadded_data).decode('utf-8')
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
