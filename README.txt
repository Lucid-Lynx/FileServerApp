Copyright 2019 by Kirill Kanin.
All rights reserved.

Description
===========

File server project.
Version: 0.9

Installing package:
python setup.py install

Start app:
fileserver [-p port] [-f folder]

Options:
-p --port - port, default: 8080
-f --folder - working directory (absolute or relative path), default: current app directory FileServer
-i --init - initialize database
-h --help - help

Launch tests:
pytest -v -s

