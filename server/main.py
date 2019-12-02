import argparse
import os
import sys
from aiohttp import web
from server.handler import Handler
from server.file_service import FileService
from server.database import DataBase


def commandline_parser() -> argparse.ArgumentParser:
    """Command line parser.

    Parse port and working directory parameters from command line.

    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', default='8080')
    parser.add_argument('-f', '--folder', default=os.getcwd())

    return parser


def main():
    """Entry point of app.

    Get and parse command line parameters and configure web app.
    Command line options:
    -p --port - port (default: 8080).
    -f --folder - working directory (absolute or relative path, default: current app folder FileServer).

    """

    parser = commandline_parser()
    namespace = parser.parse_args(sys.argv[1:])
    FileService.change_dir(namespace.folder)

    DataBase()

    handler = Handler()
    app = web.Application()
    app.add_routes([
        web.get('/', handler.handle),
        web.get('/notes', handler.get_files),
        web.get('/notes/{filename}', handler.get_file_info),
        web.post('/notes', handler.create_file),
        web.delete('/notes/{filename}', handler.delete_file),
    ])
    web.run_app(app, port=namespace.port)


if __name__ == '__main__':
    main()

