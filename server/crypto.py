import hashlib


class CryptoAPI:

    @staticmethod
    def hash_sha512(input_str: str) -> str:

        assert input_str, 'Hash: input string is not set'
        hash_obj = hashlib.sha512(input_str.encode())

        return hash_obj.hexdigest()
