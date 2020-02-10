# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import pytest
import json
import logging
import server.utils as utils
from collections import OrderedDict
# from aiohttp import web
# from server.handler import Handler
# from server.database import DataBase
from server.crypto import HashAPI, AESCipher, RSACipher
from server.file_service import FileService, FileServiceSigned

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


def create_test_files():
    full_test_file_1 = '{}/{}'.format(test_folder, test_file_1)
    with open(full_test_file_1, 'wb') as file_handler:
        data = bytes(test_content)
        file_handler.write(data)

    full_test_file_2 = '{}/{}'.format(test_folder, test_file_2)
    with open(full_test_file_2, 'wb') as file_handler:
        data = bytes(test_content)
        file_handler.write(data)

    full_test_file_3 = '{}/{}'.format(test_folder, test_file_3)
    with open(full_test_file_3, 'wb') as file_handler:
        data = bytes(test_content)
        file_handler.write(data)

    full_test_file_4 = '{}/{}'.format(test_folder, test_file_4)
    with open(full_test_file_4, 'wb') as file_handler:
        data = bytes(test_content)
        file_handler.write(data)

    full_test_file_7 = '{}/{}'.format(test_folder, test_file_7)
    with open(full_test_file_7, 'wb') as file_handler:
        data = bytes(test_content)
        file_handler.write(data)


'''
@pytest.fixture
def client(loop, aiohttp_client):

    pass
'''


@pytest.fixture(scope='function')
def prepare_data(request):
    create_and_move_to_test_folder()
    create_test_files()

    full_test_file_4 = '{}/{}'.format(test_folder, test_file_4)
    file_dict_4 = OrderedDict(
        name=test_file_4,
        create_date=utils.convert_date(os.path.getctime(full_test_file_4)),
        size=os.path.getsize(full_test_file_4),
        content=test_content)
    full_test_signature_file_4 = '{}/{}'.format(test_folder, test_signature_file_4)
    signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(file_dict_4.values()))))
    with open(full_test_signature_file_4, 'wb') as file_handler:
        data = bytes(signature)
        file_handler.write(data)

    cipher = RSACipher(test_folder)
    full_test_file_5 = '{}/{}'.format(test_folder, test_file_5)
    with open(full_test_file_5, 'wb') as file_handler:
        data = bytes(test_content)
        cipher.write_cipher_text(data, file_handler, test_file_5.split('.')[0])
    file_dict = OrderedDict(
        name=test_file_5,
        create_date=utils.convert_date(os.path.getctime(full_test_file_5)),
        size=os.path.getsize(full_test_file_5),
        content=test_content)
    full_test_signature_file_5 = '{}/{}'.format(test_folder, test_signature_file_5)
    signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(file_dict.values()))))
    with open(full_test_signature_file_5, 'wb') as file_handler:
        data = bytes(signature)
        file_handler.write(data)

    cipher = AESCipher(test_folder)
    full_test_file_6 = '{}/{}'.format(test_folder, test_file_6)
    with open(full_test_file_6, 'wb') as file_handler:
        data = bytes(test_content)
        cipher.write_cipher_text(data, file_handler, test_file_6.split('.')[0])
    file_dict = OrderedDict(
        name=test_file_6,
        create_date=utils.convert_date(os.path.getctime(full_test_file_6)),
        size=os.path.getsize(full_test_file_6),
        content=test_content)
    full_test_signature_file_6 = '{}/{}'.format(test_folder, test_signature_file_6)
    signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(file_dict.values()))))
    with open(full_test_signature_file_6, 'wb') as file_handler:
        data = bytes(signature)
        file_handler.write(data)

    full_test_file_7 = '{}/{}'.format(test_folder, test_file_7)
    file_dict_7 = OrderedDict(
        name=test_file_7,
        create_date=utils.convert_date(os.path.getctime(full_test_file_7)),
        size=os.path.getsize(full_test_file_7),
        content='Test')
    full_test_signature_file_7 = '{}/{}'.format(test_folder, test_signature_file_7)
    signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(file_dict_7.values()))))
    with open(full_test_signature_file_7, 'wb') as file_handler:
        data = bytes(signature)
        file_handler.write(data)

    request.addfinalizer(teardown)

    yield


def teardown():

    test_key_file_5 = '{}/{}.{}'.format(test_folder, test_file_5.split('.')[0], 'bin')
    test_key_file_6 = '{}/{}.{}'.format(test_folder, test_file_6.split('.')[0], 'bin')

    if os.path.exists(test_key_file_5):
        os.remove(test_key_file_5)

    if os.path.exists(test_key_file_6):
        os.remove(test_key_file_6)


class TestSuite(object):

    def test_connection(self):

        pass

    def test_get_files(self, prepare_data):

        logger.info('Test request. Access allowed')
        data = FileService(path=test_folder).get_files()
        exists_files = list(filter(
            lambda file: file.get('name') in [
                test_file_1, test_file_2, test_file_3, test_file_4, test_file_5, test_file_6, test_file_7], data))
        exists_files = list(map(lambda file: file.get('name'), exists_files))
        assert len(exists_files) == 7
        assert test_file_1 in exists_files
        assert test_file_2 in exists_files
        assert test_file_3 in exists_files
        assert test_file_4 in exists_files
        assert test_file_5 in exists_files
        assert test_file_6 in exists_files
        assert test_file_7 in exists_files
        assert not (test_file_8 in exists_files)
        logger.info('Test is succeeded')

    def test_get_file_info(self, prepare_data):
        test_file_part = test_file_4.split('.')[0]

        logger.info('Test request. File exists. Security level is low')
        data = FileService(path=test_folder).get_file_data(test_file_part)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_4
        content = data.get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is high')
        test_file_part = test_file_5.split('.')[0]
        data = FileService(path=test_folder).get_file_data(test_file_part)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_5
        content = data.get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is medium')
        test_file_part = test_file_6.split('.')[0]
        data = FileService(path=test_folder).get_file_data(test_file_part)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_6
        content = data.get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is low. Signatures are match')
        test_file_part = test_file_4.split('.')[0]
        data = FileServiceSigned(path=test_folder).get_file_data(test_file_part)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_4
        content = data.get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is high. Signatures are match')
        test_file_part = test_file_5.split('.')[0]
        data = FileServiceSigned(path=test_folder).get_file_data(test_file_part)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_5
        content = data.get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is medium. Signatures are match')
        test_file_part = test_file_6.split('.')[0]
        data = FileServiceSigned(path=test_folder).get_file_data(test_file_part)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_6
        content = data.get('content')
        assert content == test_content
        logger.info('Test is succeeded')

    def test_create_file(self, prepare_data):
        logger.info(
            'Test request. Access allowed. Content is not empty. Security level is not empty. File is not signed')
        data = FileService(path=test_folder).create_file(content=test_content, security_level='high')
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

        logger.info('Test request. Content is empty. Security level is not empty. File is not signed')
        data = FileService(path=test_folder).create_file(security_level='high')
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

        logger.info('Test request. Content is not empty. Security level is empty. File is not signed')
        data = FileService(path=test_folder).create_file(content=test_content)
        filename = data.get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

        logger.info('Test request. Content is not empty. Security level is not empty. File is signed')
        data = FileServiceSigned(path=test_folder).create_file(content=test_content, security_level='high')
        filename = data.get('name')
        signature_file = '{}.{}'.format(filename.split('.')[0], 'md5')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert os.path.exists('{}/{}'.format(test_folder, signature_file))
        logger.info('Test is succeeded')

    def test_delete_file(self, prepare_data):
        test_file_part = test_file_2.split('.')[0]

        logger.info('Test request. File exists')
        FileService(path=test_folder).delete_file(test_file_part)
        signature_file = '{}.{}'.format(test_file_part, 'md5')
        assert not os.path.exists('{}/{}'.format(test_folder, test_file_2))
        assert not os.path.exists('{}/{}'.format(test_folder, signature_file))
        logger.info('Test is succeeded')

    def test_download_file(self, prepare_data):

        pass

    def test_download_file_queued(self, prepare_data):

        pass

    def test_signup(self, prepare_data):

        pass

    def test_signin(self, prepare_data):

        pass

    def test_logout(self, prepare_data):

        pass

    def test_add_method(self, prepare_data):

        pass

    def test_delete_method(self, prepare_data):

        pass

    def test_add_role(self, prepare_data):

        pass

    def test_delete_role(self, prepare_data):

        pass

    def test_add_method_to_role(self, prepare_data):

        pass

    def test_delete_method_from_role(self, prepare_data):

        pass

    def test_change_shared_prop(self, prepare_data):

        pass

    def test_change_user_role(self, prepare_data):

        pass

    def test_change_file_dir(self, prepare_data):
        new_test_folder = '../test_folder_2'

        logger.info('Test request. Directory path is set')
        file_service = FileService(path=test_folder)
        file_service_signed = FileServiceSigned(path=test_folder)
        file_service.path = new_test_folder
        file_service_signed.path = new_test_folder
        assert file_service.path == new_test_folder
        assert file_service_signed.path == new_test_folder
        logger.info('Test is succeeded')
