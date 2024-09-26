from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import os

class KeyManager:
    def __init__(self):
        self.salt_length = 16
        self.key_length = 32

    def encrypt_private_key(self, private_key, password):
        salt = get_random_bytes(16)
        key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)
        return salt + cipher.nonce + tag + ciphertext

    def decrypt_private_key(self, encrypted_data, password):
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        tag = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]
        key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        private_key = cipher.decrypt_and_verify(ciphertext, tag)
        return private_key

    def encrypt_file(self, file_path, key):
        cipher = AES.new(key, AES.MODE_EAX)
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        with open(file_path + '.enc', 'wb') as f:
            [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
        os.remove(file_path)

    def decrypt_file(self, file_path, key):
        with open(file_path, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(file_path.replace('.enc', ''), 'wb') as f:
            f.write(plaintext)

    def encrypt_vote(self, vote, key):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(vote.encode('utf-8'))
        return (cipher.nonce + tag + ciphertext).hex()

    def decrypt_vote(self, ciphertext_hex, key):
        ciphertext = bytes.fromhex(ciphertext_hex)
        nonce = ciphertext[:16]
        tag = ciphertext[16:32]
        ciphertext = ciphertext[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def generate_keys(self):
        # Method to generate public and private keys
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def load_public_key(self, public_key_str):
        """
        Load an RSA public key form a string
        :param public_key_str: <str> The serialized public key (hex or PEM format)
        :return: <RSA.RsaKey> The RSA public key object
        """
        try:
            # Convert the string back to bytes if it's in hex format
            if isinstance(public_key_str, str):
                public_key_str = bytes.fromhex(public_key_str)

            # Import the public key
            public_key = RSA.import_key(public_key_str)
            return public_key

        except (ValueError, TypeError) as e:
            print(f"Error loading public key: {e}")
            return None
