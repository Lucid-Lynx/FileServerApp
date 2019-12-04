import argparse
import os
import sys
from aiohttp import web
from .handler import Handler
from .file_service import FileService
from .database import DataBase


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
    FileService.change_dir(namespace.folder)

    db = DataBase()
    if namespace.init:
        db.init_system()

    handler = Handler()
    app = web.Application()
    app.add_routes([
        web.get('/', handler.handle),
        web.get('/notes', handler.get_files),
        web.get('/notes/{filename}', handler.get_file_info),
        web.post('/notes', handler.create_file),
        web.delete('/notes/{filename}', handler.delete_file),
        web.post('/signup', handler.signup),
        web.post('/signin', handler.signin),
        web.get('/logout/{session_id}', handler.logout),
    ])
    web.run_app(app, port=namespace.port)


if __name__ == '__main__':
    main()
