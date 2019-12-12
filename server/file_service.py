import os
import server.utils as utils
import typing

extension = 'txt'


class FileService:
    """Class with static methods for working with file system.

    """

    __is_inited = False

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, '__instance'):
            cls.__instance = super(FileService, cls).__new__(cls)
        return cls.__instance

    def __init__(self, path):
        if not self.__is_inited:
            self.path = path
            self.__is_inited = True

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

    def get_file_data(self, filename: str) -> typing.Dict[str, str]:
        """Get full info about file.

        Args:
            filename (str): Filename without .txt file extension.

        Returns:
            Dict (key (str): value (str)), which contains full info about file. Keys:
            name: name of file with .txt extension.
            content: file content.
            create_date: date of file creation.
            edit_date: date of last file modification.
            size: size of file in bytes.

        Raises:
            AssertionError: if file does not exist.

        """

        short_filename = '{}.{}'.format(filename, extension)
        full_filename = '{}/{}.{}'.format(self.path, filename, extension)
        assert os.path.exists(full_filename), \
            'File {}.{} does not exist'.format(filename, extension)

        with open(full_filename, 'r') as file_handler:
            return {
                'name': short_filename,
                'content': file_handler.read(),
                'create_date': utils.convert_date(os.path.getctime(full_filename)),
                'edit_date': utils.convert_date(os.path.getmtime(full_filename)),
                'size': '{} bytes'.format(os.path.getsize(full_filename), 'bytes'),
            }

    def get_files(self) -> typing.List[typing.Dict[str, str]]:
        """Get info about all files in working directory.

        Returns:
            List of dicts (key (str): value (str)), which contains info about each file. Keys:
            name: name of file with .txt extension.
            create_date: date of file creation.
            edit_date: date of last file modification.
            size: size of file in bytes.

        """

        data = []
        files = [f for f in os.listdir(self.path) if os.path.isfile('{}/{}'.format(self.path, f))]

        for f in files:
            full_filename = os.path.isfile('{}/{}'.format(self.path, f))
            data.append({
                'name': f,
                'create_date': utils.convert_date(os.path.getctime(full_filename)),
                'edit_date': utils.convert_date(os.path.getmtime(full_filename)),
                'size': os.path.getsize(full_filename),
            })

        return data

    def create_file(self, content: str = None) -> typing.Dict[str, str]:
        """Create new .txt file.

        Method generates name of file from random string with digits and latin letters.

        Args:
            content (str): String with file content.

        Returns:
            Dict (key (str): value (str)), which contains name of created file. Keys:
            name: name of file with .txt extension.

        """

        filename = '{}.{}'.format(utils.generate_string(), extension)
        full_filename = '{}/{}'.format(self.path, filename)

        while os.path.exists(full_filename):
            filename = '{}.{}'.format(utils.generate_string(), extension)
            full_filename = '{}/{}'.format(self.path, filename)

        with open(full_filename, 'w') as file_handler:
            if content:
                file_handler.write(content)

        return {
            'name': filename,
        }

    def delete_file(self, filename: str):
        """Delete file.

        Args:
            filename (str): Filename without .txt file extension.

        Raises:
            AssertionError: if file does not exist.

        """

        full_filename = "{}/{}.{}".format(self.path, filename, extension)
        assert os.path.exists(full_filename), 'File {}.{} does not exist'.format(filename, extension)

        os.remove(full_filename)
