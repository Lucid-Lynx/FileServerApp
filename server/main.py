# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import argparse
import os
import sys
import logging
import json
from aiohttp import web
from server.handler import Handler
from server.database import DataBase
from server.file_service import FileService, FileServiceSigned
import server.file_service_no_class as FileServiceNoClass


def commandline_parser() -> argparse.ArgumentParser:
    """Command line parser.

    Parse port and working directory parameters from command line.

    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', default='8080', help='port (default: 8080)')
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
    -p --port - port (default: 8080).
    -f --folder - working directory (absolute or relative path, default: current app folder FileServer).
    -i --init - initialize database.
    -h --help - help.

    """

    parser = commandline_parser()
    namespace = parser.parse_args(sys.argv[1:])

    db = DataBase()
    if namespace.init:
        db.init_system()

    handler = Handler(namespace.folder)
    app = web.Application()
    app.add_routes([
        web.get('/', handler.handle),
        web.get('/files/list', handler.get_files),
        web.get('/files', handler.get_file_info),
        web.post('/files', handler.create_file),
        web.delete('/files/{filename}', handler.delete_file),
        web.post('/signup', handler.signup),
        web.post('/signin', handler.signin),
        web.get('/logout', handler.logout),
        web.put('/method/{method_name}', handler.add_method),
        web.delete('/method/{method_name}', handler.delete_method),
        web.put('/role/{role_name}', handler.add_role),
        web.delete('/role/{role_name}', handler.delete_role),
        web.post('/add_method_to_role', handler.add_method_to_role),
        web.post('/delete_method_from_role', handler.delete_method_from_role),
        web.post('/change_shared_prop', handler.change_shared_prop),
        web.post('/change_user_role', handler.change_user_role),
        web.post('/change_file_dir', handler.change_file_dir),
    ])
    logging.basicConfig(level=logging.INFO)
    web.run_app(app, port=namespace.port)


if __name__ == '__main__':
    main()
