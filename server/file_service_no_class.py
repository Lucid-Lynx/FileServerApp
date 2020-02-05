# Copyright 2019 by Kirill Kanin.
# All rights reserved.


import os
import sys
import server.utils as utils

extension = 'txt'


def change_dir(path):
    """Change current directory of app.

    Args:
        path (str): Path to working directory with files.

    Raises:
        AssertionError: if directory does not exist.

    """

    assert os.path.exists(path), 'Directory {} is not found'.format(path)
    os.chdir(path)


def get_file_data(filename):
    """Get full info about file.

    Args:
        filename (str): Filename without .txt file extension.

    Returns:
        Dict, which contains full info about file. Keys:
            name (str): name of file with .txt extension.
            content (str): file content.
            create_date (str): date of file creation.
            edit_date (str): date of last file modification.
            size (int): size of file in bytes.

    Raises:
        AssertionError: if file does not exist, filename format is invalid.

    """

    path = os.getcwd()
    short_filename = '{}.{}'.format(filename, extension)
    full_filename = '{}/{}'.format(path, short_filename)
    assert os.path.exists(full_filename), 'File {} does not exist'.format(short_filename)

    filename_parts = filename.split('_')
    assert len(filename_parts) == 2, 'Invalid format of file name'

    with open(full_filename, 'rb') as file_handler:
        return {
            'name': short_filename,
            'create_date': utils.convert_date(os.path.getctime(full_filename)),
            'edit_date': utils.convert_date(os.path.getmtime(full_filename)),
            'size': os.path.getsize(full_filename),
            'context': file_handler.read(),
        }


def get_files():
    """Get info about all files in working directory.

    Returns:
        List of dicts, which contains info about each file. Keys:
            name (str): name of file with .txt extension.
            create_date (str): date of file creation.
            edit_date (str): date of last file modification.
            size (str): size of file in bytes.

    """

    path = os.getcwd()
    data = []
    files = [f for f in os.listdir(path) if os.path.isfile('{}/{}'.format(path, f))]
    files = list([f for f in files if len(f.split('.')) > 1 and f.split('.')[1] == extension])

    for f in files:
        full_filename = '{}/{}'.format(path, f)
        data.append({
            'name': f,
            'create_date': utils.convert_date(os.path.getctime(full_filename)),
            'edit_date': utils.convert_date(os.path.getmtime(full_filename)),
            'size': '{} bytes'.format(os.path.getsize(full_filename)),
        })

    return data


def create_file(content=None):
    """Create new .txt file.

    Method generates name of file from random string with digits and latin letters.

    Args:
        content (str): String with file content.

    Returns:
        Dict, which contains name of created file. Keys:
            name (str): name of file with .txt extension.
            content (str): file content.
            create_date (str): date of file creation.
            size (int): size of file in bytes,
            user_id (int): user Id.

    Raises:
        AssertionError: if user_id is not set.

    """

    path = os.getcwd()
    filename = '{}.{}'.format(utils.generate_string(), extension)
    full_filename = '{}/{}'.format(path, filename)

    while os.path.exists(full_filename):
        filename = '{}.{}'.format(utils.generate_string(), extension)
        full_filename = '{}/{}'.format(path, filename)

    with open(full_filename, 'wb') as file_handler:
        if content:
            if sys.version_info[0] < 3:
                data = bytes(content)
            else:
                data = bytes(content, 'utf-8')
            file_handler.write(data)

    return {
        'name': filename,
        'create_date': utils.convert_date(os.path.getctime(full_filename)),
        'size': os.path.getsize(full_filename),
        'content': content,
    }


def delete_file(filename):
    """Delete file.

    Args:
        filename (str): Filename without .txt file extension.

    Returns:
        Str with filename with .txt file extension.

    Raises:
        AssertionError: if file does not exist.

    """

    path = os.getcwd()
    short_filename = '{}.{}'.format(filename, extension)
    signature_file = '{}.{}'.format(filename, 'md5')
    full_filename = "{}/{}".format(path, short_filename)
    full_signature_file = "{}/{}".format(path, signature_file)
    assert os.path.exists(full_filename), 'File {} does not exist'.format(short_filename)

    os.remove(full_filename)

    if os.path.exists(full_signature_file):
        os.remove(full_signature_file)

    return short_filename
