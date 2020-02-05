# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import argparse
import os
import sys
import logging
import json
from aiohttp import web
# from server.handler import Handler
# from server.database import DataBase
from server.file_service import FileService, FileServiceSigned
import server.file_service_no_class as FileServiceNoClass


def commandline_parser():
    """Command line parser.

    Parse port and working directory parameters from command line.

    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f', '--folder', default=os.getcwd(),
        help='working directory (absolute or relative path, default: current app folder FileServer)')
    parser.add_argument('-i', '--init', action='store_true', help='initialize database')

    return parser


def get_file_data(path):
    """Get full info about file.

    Args:
        path (str): Working directory path.

    Returns:
        Dict, which contains full info about file. Keys:
            name (str): name of file with .txt extension.
            content (str): file content.
            create_date (str): date of file creation.
            edit_date (str): date of last file modification.
            size (int): size of file in bytes.

    Raises:
        AssertionError: if file does not exist, filename format is invalid,
        ValueError: if security level is invalid.

    """

    print('Input filename (without extension):')
    filename = input()

    print('Check sign? y/n:')
    is_signed = input()

    if is_signed == 'y':
        data = FileServiceSigned(path=path).get_file_data(filename)
    elif is_signed == 'n':
        data = FileService(path=path).get_file_data(filename)
    else:
        raise ValueError('Invalid value')

    return data


def create_file(path):
    """Create new .txt file.

    Method generates name of file from random string with digits and latin letters.

    Args:
        path (str): Working directory path.

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

    print('Input content:')
    content = input()

    print('Input security level (low, medium, high):')
    security_level = input()

    assert security_level in ['low', 'medium', 'high'], 'Invalid security level'

    print('Sign file? y/n:')
    is_signed = input()

    if is_signed == 'y':
        data = FileServiceSigned(path=path).create_file(content, security_level)
    elif is_signed == 'n':
        data = FileService(path=path).create_file(content, security_level)
    else:
        raise ValueError('Invalid value')

    return data


def delete_file(path):
    """Delete file.

    Args:
        path (str): Working directory path.

    Returns:
        Str with filename with .txt file extension.

    Raises:
        AssertionError: if file does not exist.

    """

    print('Input filename (without extension):')
    filename = input()

    data = FileService(path=path).delete_file(filename)

    return data


def change_dir(path):
    """Change working directory.

    Args:
        path (str): Working directory path.

    Returns:
        Str with successfully result.

    """

    print('Input new working directory path:')
    new_path = input()

    FileService(path).path = new_path
    FileServiceSigned.path = new_path

    return 'Working directory is successfully changed. New path is {}'.format(new_path)


def main():
    """Entry point of app.

    Get and parse command line parameters and configure web app.
    Command line options:
    -f --folder - working directory (absolute or relative path, default: current app folder FileServer).
    -h --help - help.

    """

    parser = commandline_parser()
    namespace = parser.parse_args(sys.argv[1:])
    path = namespace.folder

    print('Commands:')
    print('list - get files list')
    print('get - get file data')
    print('create - create file')
    print('delete - delete file')
    print('chdir - change working directory')
    print('exit - exit from app')
    print('\n')

    while True:

        try:
            print('Input command:')
            command = input()

            if command == 'list':
                data = FileService(path=path).get_files()

            elif command == 'get':
                data = get_file_data(path)

            elif command == 'create':
                data = create_file(path)

            elif command == 'delete':
                data = delete_file(path)

            elif command == 'chdir':
                data = change_dir(path)

            elif command == 'exit':
                return

            else:
                raise ValueError('Invalid command')

            print('\n{}\n'.format({
                'status': 'success',
                'result': json.dumps(data, indent=4),
            }))

        except (ValueError, AssertionError) as err:
            print('\n{}\n'.format({
                'status': 'error',
                'message': err.message if sys.version_info[0] < 3 else err,
            }))


if __name__ == '__main__':
    main()
