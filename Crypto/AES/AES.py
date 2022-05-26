#AES implementation by Geovani Benita

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from binascii import hexlify
from hashlib import md5
from Cryptodome.Random import get_random_bytes

#base class to define de blocksize and the secret key (using hash for convenience)
class Cryptor:
    def __init__(self, secret_key: str, block_size: int = 128):
        AES.block_size = int(block_size / 8)
        self.secret_key_hash = md5(secret_key.encode()).digest()

    @staticmethod
    def bytes(data: bytes):
        return hexlify(data).decode()

#Class where I define the encryption method encrypt_data
class Encryptor(Cryptor):
    def __init__(self, secret_key: str, block_size: int = 256):
        super().__init__(secret_key, block_size)

    def encrypt_data(self, text: str):
        data = text.encode()
        random_bytes = get_random_bytes(AES.block_size)
        aes = AES.new(self.secret_key_hash, AES.MODE_CBC, random_bytes)
        encrypted_data = aes.encrypt(pad(data, AES.block_size))
        return random_bytes + encrypted_data
        
#class to decrypt the data 
class Decryptor(Cryptor):
    def __init__(self, secret_key: str, block_size: int = 256):
        super().__init__(secret_key, block_size)

    def start_decrypt(self, data: bytes):
        random_bytes = data[:AES.block_size]
        aes = AES.new(self.secret_key_hash, AES.MODE_CBC, random_bytes)
        decrypted_data = aes.decrypt(data[AES.block_size:])
        decrypted_data = unpad(decrypted_data, AES.block_size)
        return decrypted_data.decode()



SECRET_KEY = "0xc10xab0x010x280x05"

user_text = input("Type the text to encrypt: ")

encryptor = Encryptor(secret_key=SECRET_KEY, block_size=128)
encrypted_bytes = encryptor.encrypt_data(text=user_text)
print("Encrypted data (Hex):",encryptor.bytes(encrypted_bytes))
decryptor = Decryptor(secret_key=SECRET_KEY, block_size=128)
original_text = decryptor.start_decrypt(data=encrypted_bytes)

print("Decrypted data:",original_text)

