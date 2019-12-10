import server
from setuptools import setup, find_packages
from os.path import join, dirname

setup(
    name='FileServer',
    version=server.__version__,
    packages=find_packages(),
    long_description=open(join(dirname(__file__), 'README.txt')).read(),
    entry_points={
        'console_scripts': ['fileserver = server.main:main']
    },
    install_requires=[
        'aiohttp==3.6.0',
        'cchardet==2.1.4',
        'aiodns==2.0.0',
        'pytest==5.3.1',
        'pytest-aiohttp==0.3.0',
        'psycopg2==2.8.4',
        'SQLAlchemy==1.3.11',
        'uuid==1.30',
    ]
)
