# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from typing import Tuple, BinaryIO

key_folder = '../keys'


class HashAPI:

    @staticmethod
    def hash_sha512(input_str: str) -> str:

        assert input_str, 'Hash: input string is not set'
        hash_obj = hashlib.sha512(input_str.encode())

        return hash_obj.hexdigest()

    @staticmethod
    def hash_md5(input_str: str) -> str:
        assert input_str, 'Hash: input string is not set'
        hash_obj = hashlib.md5(input_str.encode())

        return hash_obj.hexdigest()


class BaseCipher:

    def __init__(self):
        if not os.path.exists(key_folder):
            os.mkdir(key_folder)

    def encrypt(self, data: bytes):
        pass

    def decrypt(self, input_file: BinaryIO) -> bytes:
        return input_file.read()

    def write_cipher_text(self, data: bytes, out_file: BinaryIO):
        out_file.write(data)


class AESCipher(BaseCipher):

    def __init__(self, user_id: int):
        super().__init__()
        self.user_id = user_id
        self.session_key_file = '{}/{}_session_aes_key.bin'.format(key_folder, self.user_id)

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipher_text, tag = cipher_aes.encrypt_and_digest(data)

        return cipher_text, tag, cipher_aes.nonce, session_key

    def decrypt(self, input_file: BinaryIO) -> bytes:
        nonce, tag, cipher_text = [input_file.read(x) for x in (16, 16, -1)]
        session_key = open(self.session_key_file, 'rb').read()

        return self.decrypt_aes_data(cipher_text, tag, nonce, session_key)

    @staticmethod
    def decrypt_aes_data(cipher_text: bytes, tag: bytes, nonce: bytes, session_key: bytes) -> bytes:
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(cipher_text, tag)

        return data

    def write_cipher_text(self, data: bytes, out_file: BinaryIO):
        cipher_text, tag, nonce, session_key = self.encrypt(data)

        if not os.path.exists(self.session_key_file):
            with open(self.session_key_file, 'wb') as f:
                f.write(session_key)

        out_file.write(nonce)
        out_file.write(tag)
        out_file.write(cipher_text)


class RSACipher(AESCipher):
    code = os.environ['CRYPTO_CODE']
    key_protection = 'scryptAndAES128-CBC'

    def __init__(self, user_id: int):
        super().__init__(user_id)
        key = RSA.generate(2048)
        encrypted_key = key.export_key(passphrase=self.code, pkcs=8, protection=self.key_protection)

        self.private_key_file = '{}/{}_private_rsa_key.bin'.format(key_folder, self.user_id)
        self.public_key_file = '{}/{}_public_rsa_key.pem'.format(key_folder, self.user_id)

        if not os.path.exists(self.private_key_file):
            with open(self.private_key_file, 'wb') as f:
                f.write(encrypted_key)

        if not os.path.exists(self.public_key_file):
            with open(self.public_key_file, 'wb') as f:
                f.write(key.publickey().exportKey())

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        cipher_text, tag, nonce, session_key = super().encrypt(data)

        public_key = RSA.import_key(open(self.public_key_file).read())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        return cipher_text, tag, nonce, enc_session_key

    def decrypt(self, input_file: BinaryIO) -> bytes:
        private_key = RSA.import_key(open(self.private_key_file).read(), passphrase=self.code)
        enc_session_key, nonce, tag, cipher_text = [
            input_file.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        return self.decrypt_aes_data(cipher_text, tag, nonce, session_key)

    def write_cipher_text(self, data: bytes, out_file: BinaryIO):
        cipher_text, tag, nonce, session_key = self.encrypt(data)
        out_file.write(session_key)
        out_file.write(nonce)
        out_file.write(tag)
        out_file.write(cipher_text)
