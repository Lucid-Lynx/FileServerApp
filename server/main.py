# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import argparse
import os
import sys
import logging
from aiohttp import web
from server.handler import Handler
from server.database import DataBase
from server.file_service import FileService, FileServiceSigned
import server.file_service_no_class as FileServiceNoClass


def commandline_parser() -> argparse.ArgumentParser:
    """Command line parser.

    Parse port and working directory parameters from command line.

    """

    pass


def main():
    """Entry point of app.

    Get and parse command line parameters and configure web app.
    Command line options:
    -p --port - port (default: 8080).
    -f --folder - working directory (absolute or relative path, default: current app folder FileServer).
    -i --init - initialize database.
    -h --help - help.

    """

    pass


if __name__ == '__main__':
    main()
