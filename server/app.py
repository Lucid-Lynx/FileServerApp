#!/usr/bin/env python

# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import argparse
import os
import sys
import logging
from aiohttp import web
from server.web.handler import Handler
from server.db.database import DataBase


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


def app():
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
        web.get('/files/download', handler.download_file),
        web.get('/files/download/queued', handler.download_file_queued),
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
    app()
