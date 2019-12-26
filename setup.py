# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import server
from setuptools import setup, find_packages
from os.path import join, dirname

setup(
    name='FileServer',
    version=server.__version__,
    packages=find_packages(),
    long_description=open(join(dirname(__file__), 'README.txt')).read(),
    entry_points={
        'console_scripts': ['fileserver = server.main:main'],
    },
    install_requires=[
        'pycryptodome==3.9.4',
    ]
)
