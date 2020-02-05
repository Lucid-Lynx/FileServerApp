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
import server.file_service_no_class as FileServerNoClass

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
    if not os.path.exists(test_folder):
        os.mkdir(test_folder)

    os.chdir(test_folder)


def create_test_files():
    full_test_file_1 = '{}/{}'.format(test_folder, test_file_1)
    with open(full_test_file_1, 'wb') as file_handler:
        data = bytes(test_content, 'utf-8')
        file_handler.write(data)

    full_test_file_2 = '{}/{}'.format(test_folder, test_file_2)
    with open(full_test_file_2, 'wb') as file_handler:
        data = bytes(test_content, 'utf-8')
        file_handler.write(data)

    full_test_file_3 = '{}/{}'.format(test_folder, test_file_3)
    with open(full_test_file_3, 'wb') as file_handler:
        data = bytes(test_content, 'utf-8')
        file_handler.write(data)

    full_test_file_4 = '{}/{}'.format(test_folder, test_file_4)
    with open(full_test_file_4, 'wb') as file_handler:
        data = bytes(test_content, 'utf-8')
        file_handler.write(data)

    full_test_file_7 = '{}/{}'.format(test_folder, test_file_7)
    with open(full_test_file_7, 'wb') as file_handler:
        data = bytes(test_content, 'utf-8')
        file_handler.write(data)


@pytest.fixture
def client(loop, aiohttp_client):

    pass


@pytest.fixture(scope='function')
def prepare_data(request):
    logger.info('Prepare test data in database')
    create_and_move_to_test_folder()
    create_test_files()
    request.addfinalizer(teardown)

    yield


def teardown():

    pass


class TestSuite:

    async def test_connection(self, prepare_data):

        pass

    def test_get_files(self, prepare_data):
        logger.info('Test request')
        data = FileServerNoClass.get_files()
        exists_files = list(filter(
            lambda file: file.get('name') in [
                test_file_1, test_file_2, test_file_3, test_file_4, test_file_7], data))
        exists_files = list(map(lambda file: file.get('name'), exists_files))
        assert len(exists_files) == 5
        assert test_file_1 in exists_files
        assert test_file_2 in exists_files
        assert test_file_3 in exists_files
        assert test_file_4 in exists_files
        assert test_file_7 in exists_files
        assert not (test_file_8 in exists_files)
        logger.info('Test is succeeded')

    def test_get_file_info(self, prepare_data):
        test_file_part = test_file_4.split('.')[0]
        logger.info('Test request')

        data = FileServerNoClass.get_file_data(test_file_part)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_4
        logger.info('Test is succeeded')

    def test_create_file(self, prepare_data):
        logger.info(
            'Test request. Content is not empty')
        data = FileServerNoClass.create_file(test_content)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

        logger.info('Test request. Content is empty')
        data = FileServerNoClass.create_file()
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

    def test_delete_file(self, prepare_data):
        test_file_part = test_file_2.split('.')[0]

        logger.info('Test request. File exists')
        FileServerNoClass.delete_file(test_file_part)
        assert not os.path.exists('{}/{}'.format(test_folder, test_file_2))
        logger.info('Test is succeeded')

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

    def test_change_file_dir(self, prepare_data):
        new_test_folder = '../test_folder_2'

        logger.info('Test request')
        FileServerNoClass.change_dir(new_test_folder)
        logger.info('Test is succeeded')
