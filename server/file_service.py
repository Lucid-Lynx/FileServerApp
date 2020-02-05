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

    def __new__(cls, *args, **kwargs):
        pass

    def __init__(self, *args, **kwargs):
        pass

    @property
    def path(self) -> str:
        """Working directory path getter.

        Returns:
            Str with working directory path.

        """

        pass

    @path.setter
    def path(self, value: str):
        """Working directory path setter.

        Args:
            value (str): Working directory path.

        """

        pass

    @staticmethod
    def change_dir(path: str):
        """Change current directory of app.

        Args:
            path (str): Path to working directory with files.

        Raises:
            AssertionError: if directory does not exist.

        """

        pass

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
            AssertionError: if file does not exist, filename format is invalid,
            ValueError: if security level is invalid.

        """

        pass

    async def get_file_data_async(self, filename: str, user_id: int = None) -> typing.Dict[str, str]:
        """Get full info about file. Asynchronous version.

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
            AssertionError: if file does not exist, filename format is invalid,
            ValueError: if security level is invalid.

        """

        pass

    def get_files(self) -> typing.List[typing.Dict[str, str]]:
        """Get info about all files in working directory.

        Returns:
            List of dicts, which contains info about each file. Keys:
                name (str): name of file with .txt extension.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (str): size of file in bytes.

        """

        pass

    async def create_file(
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

        pass

    def delete_file(self, filename: str):
        """Delete file.

        Args:
            filename (str): Filename without .txt file extension.

        Returns:
            Str with filename with .txt file extension.

        Raises:
            AssertionError: if file does not exist.

        """

        pass


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
            AssertionError: if file does not exist, filename format is invalid, signatures are not match,
            signature file does not exist,
            ValueError: if security level is invalid.

        """

        pass

    async def get_file_data_async(self, filename: str, user_id: int = None) -> typing.Dict[str, str]:
        """Get full info about file. Asynchronous version.

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
            AssertionError: if file does not exist, filename format is invalid, signatures are not match,
            signature file does not exist,
            ValueError: if security level is invalid.

        """

        pass

    async def create_file(
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

        pass
