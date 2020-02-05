# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import pytest
import json
import logging
import server.utils as utils
from collections import OrderedDict
from aiohttp import web
# from server.handler import Handler
# from server.database import DataBase
from server.crypto import HashAPI, AESCipher, RSACipher

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

extension = 'txt'
test_folder = '../test_files_1'
test_file_1 = 'test1_low.txt'
test_file_2 = 'test2_test.txt'
test_file_3 = 'test3.txt'
test_file_4 = 'test4_low.txt'
test_signature_file_4 = 'test4_low.md5'
test_file_5 = 'test5_high.txt'
test_signature_file_5 = 'test5_high.md5'
test_file_6 = 'test6_medium.txt'
test_signature_file_6 = 'test6_medium.md5'
test_file_7 = 'test7_low.txt'
test_signature_file_7 = 'test7_low.md5'
test_file_8 = 'test8_low.txt'
test_content = 'Test content/n'


def create_and_move_to_test_folder():
    pass


def create_test_files():
    pass


@pytest.fixture
def client(loop, aiohttp_client):
    pass


@pytest.fixture(scope='function')
def prepare_data(request):
    pass


def teardown():
    pass


class TestSuite:

    async def test_connection(self, client):
        pass

    async def test_get_files(self, client, prepare_data):
        pass

    async def test_get_file_info(self, client, prepare_data):
        pass

    async def test_create_file(self, client, prepare_data):
        pass

    async def test_delete_file(self, client, prepare_data):
        pass

    async def test_download_file(self, client, prepare_data):
        pass

    async def test_download_file_queued(self, client, prepare_data):
        pass

    async def test_signup(self, client, prepare_data):
        pass

    async def test_signin(self, client, prepare_data):
        pass

    async def test_logout(self, client, prepare_data):
        pass

    async def test_add_method(self, client, prepare_data):
        pass

    async def test_delete_method(self, client, prepare_data):
        pass

    async def test_add_role(self, client, prepare_data):
        pass

    async def test_delete_role(self, client, prepare_data):
        pass

    async def test_add_method_to_role(self, client, prepare_data):
        pass

    async def test_delete_method_from_role(self, client, prepare_data):
        pass

    async def test_change_shared_prop(self, client, prepare_data):
        pass

    async def test_change_user_role(self, client, prepare_data):
        pass

    async def test_change_file_dir(self, client, prepare_data):
        pass
