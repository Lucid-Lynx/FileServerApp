# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from typing import Tuple, BinaryIO

key_folder = os.environ['KEY_DIR']


class HashAPI:
    """Class with static methods for generating hashes.

    """

    @staticmethod
    def hash_sha512(input_str: str) -> str:
        """Generate hash SHA-512.

        Args:
            input_str (str): Input string.

        Returns:
            Str with hash in hex format.

        Raises:
            AssertionError: if input string is not set.

        """

        pass

    @staticmethod
    def hash_md5(input_str: str) -> str:
        """Generate hash MD5.

        Args:
            input_str (str): Input string.

        Returns:
            Str with hash in hex format.

        Raises:
            AssertionError: if input string is not set.

        """

        pass


class BaseCipher:
    """Base cipher class.

    """

    def __init__(self):
        pass

    def encrypt(self, data: bytes):
        """Encrypt data.

        Args:
            data (bytes): Input data for encrypting.

        """

        pass

    def decrypt(self, input_file: BinaryIO) -> bytes:
        """Decrypt data.

        Args:
            input_file (BinaryIO): Input file with data for decrypting.

        Returns:
            Bytes with decrypted data.

        """

        pass

    def write_cipher_text(self, data: bytes, out_file: BinaryIO):
        """Encrypt data and write cipher text into output file.

        Args:
            data (bytes): Encrypted data,
            out_file(BinaryIO): Output file.

        """

        pass


class AESCipher(BaseCipher):
    """AES cipher class.

    """

    def __init__(self, user_id: int):
        pass

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """Encrypt data.

        Args:
            data (bytes): Input data for encrypting.

        Returns:
            Tuple with bytes values, which contains cipher text, tag, nonce and session key.

        """

        pass

    def decrypt(self, input_file: BinaryIO) -> bytes:
        """Decrypt data.

        Args:
            input_file (BinaryIO): Input file with data for decrypting.

        Returns:
            Bytes with decrypted data.

        """

        pass

    @staticmethod
    def decrypt_aes_data(cipher_text: bytes, tag: bytes, nonce: bytes, session_key: bytes) -> bytes:
        """Decrypt AES data.

        Args:
            cipher_text (bytes): Cipher text for decrypting,
            tag (bytes): AES tag,
            nonce (bytes): AES nonce,
            session_key (bytes): AES session key.

        Returns:
            Bytes with decrypted data.

        """

        pass

    def write_cipher_text(self, data: bytes, out_file: BinaryIO):
        """Encrypt data and write cipher text into output file.

        Args:
            data (bytes): Encrypted data,
            out_file(BinaryIO): Output file.

        """

        pass


class RSACipher(AESCipher):
    """RSA cipher class.

    """

    def __init__(self, user_id: int):
        pass

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """Encrypt data.

        Args:
            data (bytes): Input data for encrypting.

        Returns:
            Tuple with bytes values, which contains cipher text, tag, nonce and session key.

        """

        pass

    def decrypt(self, input_file: BinaryIO) -> bytes:
        """Decrypt data.

        Args:
            input_file (BinaryIO): Input file with data for decrypting.

        Returns:
            Bytes with decrypted data.

        """

        pass

    def write_cipher_text(self, data: bytes, out_file: BinaryIO):
        """Encrypt data and write cipher text into output file.

        Args:
            data (bytes): Encrypted data,
            out_file(BinaryIO): Output file.

        """

        pass
