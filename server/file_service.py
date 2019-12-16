# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import typing
import server.utils as utils
from collections import OrderedDict
from server.crypto import BaseCipher, AESCipher, RSACipher, HashAPI


class FileService:
    """Singleton class with methods for working with file system.

    """

    __is_inited = False
    __instance = None
    extension = 'txt'

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls.__instance, cls):
            cls.__instance = super(FileService, cls).__new__(cls)
        return cls.__instance

    def __init__(self, *args, **kwargs):
        if not self.__is_inited:
            path = kwargs.get('path')

            if path:
                if not os.path.exists(path):
                    os.mkdir(path)
                self.__path = path

            self.__is_inited = True

    @property
    def path(self) -> str:
        """Working directory path getter.

        Returns:
            Str with working directory path.

        """

        return self.__path

    @path.setter
    def path(self, value: str):
        """Working directory path setter.

        Args:
            value (str): Working directory path.

        """

        if not os.path.exists(value):
            os.mkdir(value)
        self.__path = value

    @staticmethod
    def change_dir(path: str):
        """Change current directory of app.

        Args:
            path (str): Path to working directory with files.

        Raises:
            AssertionError: if directory does not exist.

        """

        assert os.path.exists(path), 'Directory {} is not found'.format(path)
        os.chdir(path)

    def get_file_data(self, filename: str, user_id: int = None) -> typing.Dict[str, str]:
        """Get full info about file.

        Args:
            filename (str): Filename without .txt file extension,
            user_id (int): User Id.

        Returns:
            Dict, which contains full info about file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if file does not exist, security level is invalid, filename format is invalid.

        """

        assert user_id, 'User Id is not set'

        short_filename = '{}.{}'.format(filename, self.extension)
        full_filename = '{}/{}'.format(self.path, short_filename)
        assert os.path.exists(full_filename), 'File {} does not exist'.format(short_filename)

        filename_parts = filename.split('_')
        assert len(filename_parts) == 2, 'Invalid format of file name'
        security_level = filename_parts[1]

        if not security_level or security_level == 'low':
            cipher = BaseCipher()
        elif security_level == 'medium':
            cipher = AESCipher(user_id)
        elif security_level == 'high':
            cipher = RSACipher(user_id)
        else:
            raise ValueError('Security level is invalid')

        with open(full_filename, 'rb') as file_handler:
            return OrderedDict(
                name=short_filename,
                create_date=utils.convert_date(os.path.getctime(full_filename)),
                edit_date=utils.convert_date(os.path.getmtime(full_filename)),
                size=os.path.getsize(full_filename),
                content=cipher.decrypt(file_handler).decode('utf-8'),
                user_id=user_id)

    def get_files(self) -> typing.List[typing.Dict[str, str]]:
        """Get info about all files in working directory.

        Returns:
            List of dicts, which contains info about each file. Keys:
                name (str): name of file with .txt extension.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (str): size of file in bytes.

        """

        data = []
        files = [f for f in os.listdir(self.path) if os.path.isfile('{}/{}'.format(self.path, f))]
        files = list(filter(lambda f: len(f.split('.')) > 1 and f.split('.')[1] == self.extension, files))

        for f in files:
            full_filename = '{}/{}'.format(self.path, f)
            data.append({
                'name': f,
                'create_date': utils.convert_date(os.path.getctime(full_filename)),
                'edit_date': utils.convert_date(os.path.getmtime(full_filename)),
                'size': '{} bytes'.format(os.path.getsize(full_filename))
            })

        return data

    def create_file(
            self, content: str = None, security_level: str = None, user_id: int = None) -> typing.Dict[str, str]:
        """Create new .txt file.

        Method generates name of file from random string with digits and latin letters.

        Args:
            content (str): String with file content,
            security_level (str): String with security level,
            user_id (int): User Id.

        Returns:
            Dict, which contains name of created file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if user_id is not set,
            ValueError: if security level is invalid.

        """

        assert user_id, 'User Id is not set'

        filename = '{}_{}.{}'.format(utils.generate_string(), security_level, self.extension)
        full_filename = '{}/{}'.format(self.path, filename)

        while os.path.exists(full_filename):
            filename = '{}_{}.{}'.format(utils.generate_string(), security_level, self.extension)
            full_filename = '{}/{}'.format(self.path, filename)

        if not security_level or security_level == 'low':
            cipher = BaseCipher()
        elif security_level == 'medium':
            cipher = AESCipher(user_id)
        elif security_level == 'high':
            cipher = RSACipher(user_id)
        else:
            raise ValueError('Security level is invalid')

        with open(full_filename, 'wb') as file_handler:
            if content:
                data = bytes(content, 'utf-8')
                cipher.write_cipher_text(data, file_handler)

        return OrderedDict(
            name=filename,
            create_date=utils.convert_date(os.path.getctime(full_filename)),
            size=os.path.getsize(full_filename),
            content=content,
            user_id=user_id)

    def delete_file(self, filename: str):
        """Delete file.

        Args:
            filename (str): Filename without .txt file extension.

        Returns:
            Str with filename with .txt file extension.

        Raises:
            AssertionError: if file does not exist.

        """

        short_filename = '{}.{}'.format(filename, self.extension)
        signature_file = '{}.{}'.format(filename, 'md5')
        full_filename = "{}/{}".format(self.path, short_filename)
        full_signature_file = "{}/{}".format(self.path, signature_file)
        assert os.path.exists(full_filename), 'File {} does not exist'.format(short_filename)

        os.remove(full_filename)

        if os.path.exists(full_signature_file):
            os.remove(full_signature_file)

        return short_filename


class FileServiceSigned(FileService):
    """Singleton class with methods for working with file system and file signatures.

    """

    def get_file_data(self, filename: str, user_id: int = None) -> typing.Dict[str, str]:
        """Get full info about file.

       Args:
            filename (str): Filename without .txt file extension,
            user_id (int): User Id.

        Returns:
            Dict, which contains full info about file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if file does not exist, security level is invalid, filename format is invalid, signatures
            are not match, signature file does not exist.

        """

        result = super().get_file_data(filename, user_id)
        result_for_check = result
        result_for_check.pop('edit_date')

        short_filename = '{}.{}'.format(filename, 'md5')
        full_filename = '{}/{}'.format(self.path, short_filename)
        assert os.path.exists(full_filename), 'Signature file {} does not exist'.format(short_filename)

        signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(result_for_check.values()))))

        with open(full_filename, 'rb') as file_handler:
            assert file_handler.read() == bytes(signature, 'utf-8'), 'Signatures are not match'

        return result

    def create_file(
            self, content: str = None, security_level: str = None, user_id: int = None) -> typing.Dict[str, str]:
        """Create new .txt file with signature file.

        Method generates name of file from random string with digits and latin letters.

        Args:
            content (str): String with file content,
            security_level (str): String with security level,
            user_id (int): User Id.

        Returns:
            Dict, which contains name of created file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if user_id is not set,
            ValueError: if security level is invalid.

        """

        result = super().create_file(content, security_level, user_id)
        signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(result.values()))))
        filename = '{}.{}'.format(result['name'].split('.')[0], 'md5')
        full_filename = '{}/{}'.format(self.path, filename)

        with open(full_filename, 'wb') as file_handler:
            data = bytes(signature, 'utf-8')
            file_handler.write(data)

        return result
