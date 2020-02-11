# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import pytest
import json
import logging
import server.utils as utils
from collections import OrderedDict
from aiohttp import web
from server.handler import Handler
from server.database import DataBase
from server.crypto import HashAPI, AESCipher, RSACipher
from server.file_service import FileService, FileServiceSigned
import server.file_service_no_class as FileServiceNoClass

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
    create_and_move_to_test_folder()
    create_test_files()

    handler = Handler(test_folder)
    app = web.Application()
    app.router.add_get('/', handler.handle)
    app.router.add_get('/files/list', handler.get_files)
    app.router.add_get('/files', handler.get_file_info)
    app.router.add_post('/files', handler.create_file)
    app.router.add_delete('/files/{filename}', handler.delete_file)
    app.router.add_post('/signup', handler.signup)
    app.router.add_post('/signin', handler.signin)
    app.router.add_get('/logout', handler.logout)
    app.router.add_post('/change_file_dir', handler.change_file_dir)

    return loop.run_until_complete(aiohttp_client(app)), handler


@pytest.fixture(scope='function')
def prepare_data(request):
    logger.info('Prepare test data in database')
    db = DataBase()
    db_session = db.create_session()
    session = db.Session(
        db.User('user2@test.su', HashAPI.hash_sha512('2test1234'), 'User2'))
    user_without_session = db.User('user4@test.su', HashAPI.hash_sha512('4test1234'), 'User4')
    db_session.add_all([session, user_without_session])
    db_session.commit()

    user = db_session.query(db.User).filter_by(email='user2@test.su').first()

    full_test_file_4 = '{}/{}'.format(test_folder, test_file_4)
    file_dict_4 = OrderedDict(
        name=test_file_4,
        create_date=utils.convert_date(os.path.getctime(full_test_file_4)),
        size=os.path.getsize(full_test_file_4),
        content=test_content,
        user_id=user.id)
    full_test_signature_file_4 = '{}/{}'.format(test_folder, test_signature_file_4)
    signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(file_dict_4.values()))))
    with open(full_test_signature_file_4, 'wb') as file_handler:
        data = bytes(signature, 'utf-8')
        file_handler.write(data)

    cipher = RSACipher(user.id, test_folder)
    full_test_file_5 = '{}/{}'.format(test_folder, test_file_5)
    with open(full_test_file_5, 'wb') as file_handler:
        data = bytes(test_content, 'utf-8')
        cipher.write_cipher_text(data, file_handler, test_file_5.split('.')[0])
    file_dict = OrderedDict(
        name=test_file_5,
        create_date=utils.convert_date(os.path.getctime(full_test_file_5)),
        size=os.path.getsize(full_test_file_5),
        content=test_content,
        user_id=user.id)
    full_test_signature_file_5 = '{}/{}'.format(test_folder, test_signature_file_5)
    signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(file_dict.values()))))
    with open(full_test_signature_file_5, 'wb') as file_handler:
        data = bytes(signature, 'utf-8')
        file_handler.write(data)

    cipher = AESCipher(user.id, test_folder)
    full_test_file_6 = '{}/{}'.format(test_folder, test_file_6)
    with open(full_test_file_6, 'wb') as file_handler:
        data = bytes(test_content, 'utf-8')
        cipher.write_cipher_text(data, file_handler, test_file_6.split('.')[0])
    file_dict = OrderedDict(
        name=test_file_6,
        create_date=utils.convert_date(os.path.getctime(full_test_file_6)),
        size=os.path.getsize(full_test_file_6),
        content=test_content,
        user_id=user.id)
    full_test_signature_file_6 = '{}/{}'.format(test_folder, test_signature_file_6)
    signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(file_dict.values()))))
    with open(full_test_signature_file_6, 'wb') as file_handler:
        data = bytes(signature, 'utf-8')
        file_handler.write(data)

    full_test_file_7 = '{}/{}'.format(test_folder, test_file_7)
    file_dict_7 = OrderedDict(
        name=test_file_7,
        create_date=utils.convert_date(os.path.getctime(full_test_file_7)),
        size=os.path.getsize(full_test_file_7),
        content='Test',
        user_id=user.id)
    full_test_signature_file_7 = '{}/{}'.format(test_folder, test_signature_file_7)
    signature = HashAPI.hash_md5('_'.join(list(str(x) for x in list(file_dict_7.values()))))
    with open(full_test_signature_file_7, 'wb') as file_handler:
        data = bytes(signature, 'utf-8')
        file_handler.write(data)

    request.addfinalizer(teardown)

    yield session


def teardown():
    logger.info('Clean test data in database')
    db = DataBase()
    db_session = db.create_session()
    test_user_with_session = db_session.query(db.User).filter_by(email='user2@test.su').first()
    test_user_without_session = db_session.query(db.User).filter_by(email='user4@test.su').first()
    test_user = db_session.query(db.User).filter_by(email='user5@test.su').first()

    if test_user_with_session:
        db_session.delete(test_user_with_session)

    if test_user_without_session:
        db_session.delete(test_user_without_session)

    if test_user:
        db_session.delete(test_user)

    db_session.commit()


class TestSuite:

    async def test_connection(self, client):
        client, handler = tuple(client)

        logger.info('Test request. Method not allowed')
        resp = await client.put('/')
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request')
        resp = await client.get('/')
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        logger.info('Test is succeeded')

    async def test_get_files(self, client, prepare_data):
        client, handler = tuple(client)
        session = prepare_data

        logger.info('Test request. Method not allowed')
        resp = await client.put('/files/list')
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request. User is not logged in')
        resp = await client.get('/files/list')
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logger.info('Test is succeeded')

        logger.info('Test request. Session expired')
        resp = await client.get('/files/list', headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logger.info('Test is succeeded')

        logger.info('Test request')
        resp = await client.get('/files/list', headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        data = result.get('data')
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

    async def test_get_file_info(self, client, prepare_data):
        client, handler = tuple(client)
        session = prepare_data
        test_file_part = test_file_4.split('.')[0]

        logger.info('Test request. Method not allowed')
        resp = await client.put('/files?filename={}&is_signed={}'.format(test_file_part, 'false'))
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request. User is not logged in')
        resp = await client.get('/files?filename={}&is_signed={}'.format(test_file_part, 'false'))
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logger.info('Test is succeeded')

        logger.info('Test request. Session expired')
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'false'), headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logger.info('Test is succeeded')

        logger.info('Test request. File name is not set')
        resp = await client.get(
            '/files?is_signed={}'.format(False),
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Parameter \'filename\' is not set'
        logger.info('Test is succeeded')

        logger.info('Test request. Is_signed is not set')
        resp = await client.get(
            '/files?filename={}'.format(test_file_part),
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Parameter \'is_signed\' is not set'
        logger.info('Test is succeeded')

        logger.info('Test request. Is_signed is invalid')
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'test'),
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Is_signed is invalid'
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is low')
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'false'),
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_4
        content = result.get('data').get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is high')
        test_file_part = test_file_5.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'false'),
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_5
        content = result.get('data').get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is medium')
        test_file_part = test_file_6.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'false'),
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_6
        content = result.get('data').get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is low. Signatures are match')
        test_file_part = test_file_4.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'true'),
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_4
        content = result.get('data').get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is high. Signatures are match')
        test_file_part = test_file_5.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'true'),
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_5
        content = result.get('data').get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. File exists. Security level is medium. Signatures are match')
        test_file_part = test_file_6.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'true'),
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_6
        content = result.get('data').get('content')
        assert content == test_content
        logger.info('Test is succeeded')

        logger.info('Test request. Security level is invalid')
        test_file_part = test_file_2.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'false'),
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Security level is invalid'
        logger.info('Test is succeeded')

        logger.info('Test request. File name is invalid')
        test_file_part = test_file_3.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'false'),
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Invalid format of file name'
        logger.info('Test is succeeded')

        logger.info('Test request. File does not exist')
        test_file_part = test_file_8.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'false'),
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'File {} does not exist'.format(test_file_8)
        assert not os.path.exists('{}/{}'.format(test_folder, test_file_8))
        logger.info('Test is succeeded')

        logger.info('Test request. Signature file does not exist')
        test_file_part = test_file_1.split('.')[0]
        signature_file = '{}.{}'.format(test_file_part, 'md5')
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'true'),
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Signature file {} does not exist'.format(signature_file)
        logger.info('Test is succeeded')

        logger.info('Test request. Signatures are not match')
        test_file_part = test_file_7.split('.')[0]
        resp = await client.get(
            '/files?filename={}&is_signed={}'.format(test_file_part, 'true'),
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Signatures are not match'
        logger.info('Test is succeeded')

    async def test_create_file(self, client, prepare_data):
        client, handler = tuple(client)
        session = prepare_data

        logger.info('Test request. Method not allowed')
        resp = await client.put('/files', json={'content': test_content, 'security_level': 'high'})
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request. User is not logged in')
        resp = await client.post('/files', json={'content': test_content, 'security_level': 'high'})
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logger.info('Test is succeeded')

        logger.info('Test request. Session expired')
        resp = await client.post(
            '/files',
            json={'content': test_content, 'security_level': 'high'},
            headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logger.info('Test is succeeded')

        logger.info('Test request. Security level is invalid')
        resp = await client.post(
            '/files',
            json={'content': test_content, 'security_level': 'test'},
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Security level is invalid'
        logger.info('Test is succeeded')

        logger.info(
            'Test request. Content is not empty. Security level is not empty. File is not signed')
        resp = await client.post(
            '/files',
            json={'content': test_content, 'security_level': 'high', 'is_signed': False},
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

        logger.info('Test request. Content is empty. Security level is not empty. File is not signed')
        resp = await client.post(
            '/files',
            json={'security_level': 'high', 'is_signed': False},
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

        logger.info('Test request. Content is not empty. Security level is empty. File is not signed')
        resp = await client.post(
            '/files',
            json={'content': test_content, 'is_signed': False},
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

        logger.info('Test request. Content is not empty. Security level is not empty. File is signed')
        resp = await client.post(
            '/files',
            json={'content': test_content, 'security_level': 'high', 'is_signed': True},
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        signature_file = '{}.{}'.format(filename.split('.')[0], 'md5')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert os.path.exists('{}/{}'.format(test_folder, signature_file))
        logger.info('Test is succeeded')

        logger.info(
            'Test request. Content is not empty. Security level is not empty. '
            'Is_signed parameter is not set')
        resp = await client.post(
            '/files',
            json={'content': test_content, 'security_level': 'high'},
            headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logger.info('Test is succeeded')

        logger.info('Test request. Is_signed parameter is invalid')
        resp = await client.post(
            '/files',
            json={'content': test_content, 'security_level': 'test', 'is_signed': 'test'},
            headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Is_signed should be boolean'
        logger.info('Test is succeeded')

    async def test_delete_file(self, client, prepare_data):
        client, handler = tuple(client)
        session = prepare_data
        test_file_part = test_file_2.split('.')[0]

        logger.info('Test request. Method not allowed')
        resp = await client.put('/files/{}'.format(test_file_part))
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request. User is not logged in')
        resp = await client.delete('/files/{}'.format(test_file_part))
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logger.info('Test is succeeded')

        logger.info('Test request. Session expired')
        resp = await client.delete('/files/{}'.format(test_file_part), headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logger.info('Test is succeeded')

        logger.info('Test request. File exists')
        resp = await client.delete('/files/{}'.format(test_file_part), headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'File {} is successfully deleted'.format(test_file_2)
        signature_file = '{}.{}'.format(test_file_part, 'md5')
        assert not os.path.exists('{}/{}'.format(test_folder, test_file_2))
        assert not os.path.exists('{}/{}'.format(test_folder, signature_file))
        logger.info('Test is succeeded')

        logger.info('Test request. File does not exist')
        test_file_part = test_file_8.split('.')[0]
        resp = await client.delete('/files/{}'.format(test_file_part), headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'File {} does not exist'.format(test_file_8)
        assert not os.path.exists('{}/{}'.format(test_folder, test_file_8))
        logger.info('Test is succeeded')

    async def test_download_file(self, client, prepare_data):

        pass

    async def test_download_file_queued(self, client, prepare_data):

        pass

    async def test_signup(self, client, prepare_data):
        client, handler = tuple(client)
        test_email = 'user5@test.su'
        db = DataBase()
        db_session = db.create_session()

        logger.info('Test request. Method not allowed')
        resp = await client.put('/signup', json={
            'email': test_email,
            'password': '5test1234',
            'confirm_password': '5test1234',
            'name': 'User5',
        })
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request. User does not exist')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': '5test1234',
            'confirm_password': '5test1234',
            'name': 'User5',
        })
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'User with email {} is successfully registered'.format(test_email)
        assert db_session.query(db.User).filter_by(email=test_email).first()
        logger.info('Test is succeeded')

        logger.info('Test request. Email is not set')
        resp = await client.post('/signup', json={
            'password': '5test1234',
            'confirm_password': '5test1234',
            'name': 'User5',
        })
        assert resp.status == 400
        assert await resp.text() == 'Email is not set'
        logger.info('Test is succeeded')

        logger.info('Test request. Invalid email format')
        resp = await client.post('/signup', json={
            'email': 'user5',
            'password': '5test1234',
            'confirm_password': '5test1234',
            'name': 'User5',
        })
        assert resp.status == 400
        assert await resp.text() == 'Invalid email format'
        logger.info('Test is succeeded')

        logger.info('Test request. Password is not set')
        resp = await client.post('/signup', json={'email': test_email, 'name': 'User5'})
        assert resp.status == 400
        assert await resp.text() == 'Password is not set'
        logger.info('Test is succeeded')

        logger.info('Test request. Invalid password')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': 'test',
            'confirm_password': '5test1234',
            'name': 'User5',
        })
        assert resp.status == 400
        assert await resp.text() == \
            'Invalid password. Password should contain letters, digits and will be 8 to 50 characters long'
        logger.info('Test is succeeded')

        logger.info('Test request. Password is not confirmed')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': '5test1234',
            'name': 'User5',
        })
        assert resp.status == 400
        assert await resp.text() == 'Please, repeat the password'
        logger.info('Test is succeeded')

        logger.info('Test request. Passwords are not match')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': '5test1234',
            'confirm_password': '5test12345',
            'name': 'User5',
        })
        assert resp.status == 400
        assert await resp.text() == 'Passwords are not match'
        logger.info('Test is succeeded')

        logger.info('Test request. Name is not set')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': '5test1234',
            'confirm_password': '5test1234',
        })
        assert resp.status == 400
        assert await resp.text() == 'Name is not set'
        logger.info('Test is succeeded')

        logger.info('Test request. User exists')
        test_email_exists = 'user1@test.su'
        resp = await client.post('/signup', json={
            'email': test_email_exists,
            'password': '5test1234',
            'confirm_password': '5test1234',
            'name': 'User5',
        })
        assert resp.status == 400
        assert await resp.text() == 'User with email {} already exists'.format(test_email_exists)
        logger.info('Test is succeeded')

    async def test_signin(self, client, prepare_data):
        client, handler = tuple(client)
        session = prepare_data
        test_email = 'user2@test.su'
        db = DataBase()
        db_session = db.create_session()
        test_user = db_session.query(db.User).filter_by(email=test_email).first()

        logger.info('Test request. Method not allowed')
        resp = await client.put('/signin', json={'email': test_email, 'password': '2test1234'})
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request. User exists. Session exists')
        resp = await client.post('/signin', json={'email': test_email, 'password': '2test1234'})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully signed in system'
        assert result.get('session_id') == session.uuid
        assert db_session.query(db.Session).filter_by(user=test_user).first()
        assert len(db_session.query(db.Session).filter_by(user=test_user).all()) == 1
        logger.info('Test is succeeded')

        logger.info('Test request. Email is not set')
        resp = await client.post('/signin', json={'password': '2test1234'})
        assert resp.status == 400
        assert await resp.text() == 'Email is not set'
        logger.info('Test is succeeded')

        logger.info('Test request. Invalid email format')
        resp = await client.post('/signin', json={'email': 'user1', 'password': '2test1234'})
        assert resp.status == 400
        assert await resp.text() == 'Invalid email format'
        logger.info('Test is succeeded')

        logger.info('Test request. Password is not set')
        resp = await client.post('/signin', json={'email': test_email})
        assert resp.status == 400
        assert await resp.text() == 'Password is not set'
        logger.info('Test is succeeded')

        logger.info('Test request. Invalid password')
        resp = await client.post('/signin', json={'email': test_email, 'password': 'test'})
        assert resp.status == 400
        assert await resp.text() == 'Incorrect login or password'
        logger.info('Test is succeeded')

        logger.info('Test request. User does not exist')
        resp = await client.post('/signin', json={'email': 'user6@test.su', 'password': 'test'})
        assert resp.status == 400
        assert await resp.text() == 'Incorrect login or password'
        logger.info('Test is succeeded')

        logger.info('Test request. User exists. Session does not exist')
        test_email = 'user4@test.su'
        resp = await client.post('/signin', json={'email': test_email, 'password': '4test1234'})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully signed in system'
        assert db_session.query(db.Session).filter_by(user=test_user).first()
        assert len(db_session.query(db.Session).filter_by(user=test_user).all()) == 1
        logger.info('Test is succeeded')

    async def test_logout(self, client, prepare_data):
        client, handler = tuple(client)
        session = prepare_data
        db = DataBase()
        db_session = db.create_session()

        logger.info('Test request. Method not allowed')
        resp = await client.put('/logout')
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request. User is not logged in')
        resp = await client.get('/logout')
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logger.info('Test is succeeded')

        logger.info('Test request. User is logged in')
        resp = await client.get('/logout', headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully logged out'
        assert not db_session.query(db.Session).filter_by(uuid=session.uuid).first()
        logger.info('Test is succeeded')

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
        client, handler = tuple(client)
        session = prepare_data
        new_test_folder = '../test_folder_2'

        logger.info('Test request. Method not allowed')
        resp = await client.get('/change_file_dir', json={'path': new_test_folder})
        assert resp.status == 405
        logger.info('Test is succeeded')

        logger.info('Test request. User is not logged in')
        resp = await client.post('/change_file_dir', json={'path': new_test_folder})
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logger.info('Test is succeeded')

        logger.info('Test request. Session expired')
        resp = await client.post('/change_file_dir', json={'path': new_test_folder}, headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logger.info('Test is succeeded')

        logger.info('Test request. Directory path is not set')
        resp = await client.post('/change_file_dir', json={}, headers={'Authorization': session.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Directory path is not set'
        logger.info('Test is succeeded')

        logger.info('Test request. Directory path is set')
        resp = await client.post(
            '/change_file_dir', json={'path': new_test_folder}, headers={'Authorization': session.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == \
            'You successfully changed working directory path. New path is {}'.format(new_test_folder)
        assert handler.file_service.path == new_test_folder
        assert handler.file_service_signed.path == new_test_folder
        logger.info('Test is succeeded')
