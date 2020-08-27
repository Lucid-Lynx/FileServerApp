Copyright 2019 by Kirill Kanin.
All rights reserved.

Description
===========

File server project.
Version: 1.13.3

Installing package:
python setup.py install

or:
pip install .

In Linux 'python' command can be dropped out:
./setup.py install

Uninstalling package:
pip uninstall . -y

or:
pip uninstall fileserver -y

Start app:
fileserver [-p port] [-f folder]

Options:
-p --port - port, default: 8080
-f --folder - working directory (absolute or relative path), default: current app directory FileServer
-i --init - initialize database
-h --help - help

Launch tests:
pytest -v -s

Non package mode:
1. Prepare Python 3.8 environment
2. Install packages from requirements: 
pip -r requirements.txt

3. Start app with options described above: 
python main.py

In Linux 'python' command can be dropped out:
./main.py
