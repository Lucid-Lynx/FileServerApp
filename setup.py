#!/usr/bin/env python

# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import server
import pathlib
from setuptools import setup, find_packages
from pkg_resources import parse_requirements
from os.path import join, dirname

with pathlib.Path('requirements.txt').open() as requirements:
    install_requires = [str(req) for req in parse_requirements(requirements)]

setup(
    name='FileServer',
    version=server.__version__,
    packages=find_packages(),
    long_description=open(join(dirname(__file__), 'README.md')).read(),
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    entry_points={
        'console_scripts': ['fileserver = server.app:app'],
    },
    install_requires=install_requires,
)
