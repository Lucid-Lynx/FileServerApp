import os
import pytest
import json
import logging
from aiohttp import web
from server.handler import Handler
from server.database import DataBase
from server.file_service import FileService
from server.crypto import HashAPI

logger = logging.getLogger("Test Logger")

extension = 'txt'
test_folder = '../test_files_1'
test_file_1 = 'test1_low.txt'
test_file_2 = 'test2_test.txt'
test_file_3 = 'test3.txt'
test_file_4 = 'test4_low.txt'
test_content = 'Test content/n'


def create_and_move_to_test_folder():
    if not os.path.exists(test_folder):
        os.mkdir(test_folder)


def create_test_files():
    full_test_file_1 = '{}/{}'.format(test_folder, test_file_1)
    if not os.path.exists(full_test_file_1):
        with open(full_test_file_1, 'w') as file_handler:
            file_handler.write(test_content)

    full_test_file_2 = '{}/{}'.format(test_folder, test_file_2)
    if not os.path.exists(full_test_file_2):
        with open(full_test_file_2, 'w') as file_handler:
            file_handler.write(test_content)

    full_test_file_3 = '{}/{}'.format(test_folder, test_file_3)
    if not os.path.exists(full_test_file_3):
        with open(full_test_file_3, 'w') as file_handler:
            file_handler.write(test_content)


@pytest.fixture
def client(loop, aiohttp_client):
    create_and_move_to_test_folder()
    create_test_files()

    handler = Handler(test_folder)
    app = web.Application()
    app.router.add_get('/', handler.handle)
    app.router.add_get('/files', handler.get_files)
    app.router.add_get('/files/{filename}', handler.get_file_info)
    app.router.add_get('/files/{filename}/signed', handler.get_file_info_signed)
    app.router.add_post('/files', handler.create_file)
    app.router.add_delete('/files/{filename}', handler.delete_file)
    app.router.add_post('/signup', handler.signup)
    app.router.add_post('/signin', handler.signin)
    app.router.add_get('/logout', handler.logout)
    app.router.add_put('/method/{method_name}', handler.add_method)
    app.router.add_delete('/method/{method_name}', handler.delete_method)
    app.router.add_put('/role/{role_name}', handler.add_role)
    app.router.add_delete('/role/{role_name}', handler.delete_role)
    app.router.add_post('/add_method_to_role', handler.add_method_to_role)
    app.router.add_post('/delete_method_from_role', handler.delete_method_from_role)
    app.router.add_post('/change_shared_prop', handler.change_shared_prop)
    app.router.add_post('/change_user_role', handler.change_user_role)
    app.router.add_post('/change_file_dir', handler.change_file_dir)

    return loop.run_until_complete(aiohttp_client(app)), handler


@pytest.fixture(scope='function')
def prepare_data(request):
    logger.info('Prepare test data in database')
    db = DataBase()
    db_session = db.create_session()
    testing_methods = db_session.query(db.Method).filter(db.Method.name.in_([
        'get_files', 'get_file_info', 'create_file', 'delete_file', 'add_method', 'delete_method', 'add_role',
        'delete_role', 'add_method_to_role', 'delete_method_from_role', 'change_shared_prop', 'change_user_role',
        'change_file_dir'])).all()
    test_method = db.Method('test_method_1')
    testing_methods.append(test_method)
    test_role_denied = db.Role('test_role_1')
    test_role_allowed = db.Role('test_role_2', methods=testing_methods)
    test_role_no_user = db.Role('test_role_3')
    session_denied = db.Session(
        db.User('user1@test.su', HashAPI.hash_sha512('1test1234'), 'User1', role=test_role_denied))
    session_allowed = db.Session(
        db.User('user2@test.su', HashAPI.hash_sha512('2test1234'), 'User2', role=test_role_allowed))
    session_no_role = db.Session(
        db.User('user3@test.su', HashAPI.hash_sha512('3test1234'), 'User3'))
    db_session.add_all([session_denied, session_allowed, session_no_role, test_role_no_user])
    db_session.commit()

    request.addfinalizer(teardown)

    yield session_denied, session_allowed, session_no_role


def teardown():
    logger.info('Clean test data in database')
    db = DataBase()
    db_session = db.create_session()
    test_user_no_role = db_session.query(db.User).filter_by(email='user3@test.su').first()
    test_user = db_session.query(db.User).filter_by(email='user4@test.su').first()
    test_role_denied = db_session.query(db.Role).filter_by(name='test_role_1').first()
    test_role_allowed = db_session.query(db.Role).filter_by(name='test_role_2').first()
    test_role_no_user = db_session.query(db.Role).filter_by(name='test_role_3').first()
    test_role = db_session.query(db.Role).filter_by(name='test_role_4').first()
    test_method_1 = db_session.query(db.Method).filter_by(name='test_method_1').first()
    test_method_2 = db_session.query(db.Method).filter_by(name='test_method_2').first()

    if test_user_no_role:
        db_session.delete(test_user_no_role)

    if test_user:
        db_session.delete(test_user)

    if test_role_denied:
        db_session.query(db.MethodRole).filter_by(role_id=test_role_denied.id).delete()
        db_session.delete(test_role_denied)

    if test_role_allowed:
        db_session.query(db.MethodRole).filter_by(role_id=test_role_allowed.id).delete()
        db_session.delete(test_role_allowed)

    if test_role_no_user:
        db_session.delete(test_role_no_user)

    if test_role:
        db_session.delete(test_role)

    if test_method_1:
        db_session.query(db.MethodRole).filter_by(method_id=test_method_1.id).delete()
        db_session.delete(test_method_1)

    if test_method_2:
        db_session.query(db.MethodRole).filter_by(method_id=test_method_2.id).delete()
        db_session.delete(test_method_2)

    db_session.commit()


class TestSuite:

    async def test_connection(self, client):
        client, handler = tuple(client)

        logging.info('Test request. Method not allowed')
        resp = await client.put('/')
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request')
        resp = await client.get('/')
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        logging.info('Test is succeeded')

    async def test_get_files(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)

        logging.info('Test request. Method not allowed')
        resp = await client.put('/notes')
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.get('/notes')
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.get('/notes', headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.get('/notes', headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.get('/notes', headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed')
        resp = await client.get('/notes', headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        data = result.get('data')
        exists_files = list(filter(
            lambda file: file.get('name') in [test_file_1, test_file_2, test_file_3], data))
        exists_files = list(map(lambda file: file.get('name'), exists_files))
        assert len(exists_files) == 3
        assert test_file_1 in exists_files
        assert test_file_2 in exists_files
        assert test_file_3 in exists_files
        assert not (test_file_4 in exists_files)
        logging.info('Test is succeeded')

    async def test_get_file_info(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_file_part = test_file_1.split('.')[0]

        logging.info('Test request. Method not allowed')
        resp = await client.put('/notes/{}'.format(test_file_part))
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.get('/notes/{}'.format(test_file_part))
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. File exists')
        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        assert filename == test_file_1
        content = result.get('data').get('content')
        assert content == test_content
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Security level is invalid')
        test_file_part = test_file_2.split('.')[0]
        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Security level is invalid'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. File name is invalid')
        test_file_part = test_file_3.split('.')[0]
        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Invalid format of file name'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. File does not exist')
        test_file_part = test_file_4.split('.')[0]
        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'File {} does not exist'.format(test_file_4)
        assert not os.path.exists('{}/{}'.format(test_folder, test_file_4))
        logging.info('Test is succeeded')

    async def test_create_file(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)

        logging.info('Test request. Method not allowed')
        resp = await client.put('/notes', json={'content': test_content, 'security_level': 'high'})
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.post('/notes', json={'content': test_content, 'security_level': 'high'})
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.post(
            '/notes',
            json={'content': test_content, 'security_level': 'high'},
            headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.post(
            '/notes',
            json={'content': test_content, 'security_level': 'high'},
            headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.post(
            '/notes',
            json={'content': test_content, 'security_level': 'high'},
            headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Security level is invalid')
        resp = await client.post(
            '/notes',
            json={'content': test_content, 'security_level': 'test'},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Security level is invalid'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Content is not empty. Security level is not empty')
        resp = await client.post(
            '/notes',
            json={'content': test_content, 'security_level': 'high'},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Content is empty. Security level is not empty')
        resp = await client.post(
            '/notes', json={'security_level': 'high'}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Content is not empty. Security level is empty')
        resp = await client.post(
            '/notes', json={'content': test_content}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists('{}/{}'.format(test_folder, filename))
        logging.info('Test is succeeded')

    async def test_delete_file(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_file_part = test_file_2.split('.')[0]

        logging.info('Test request. Method not allowed')
        resp = await client.put('/notes/{}'.format(test_file_part))
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.delete('/notes/{}'.format(test_file_part))
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.delete('/notes/{}'.format(test_file_part), headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.delete('/notes/{}'.format(test_file_part), headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.delete('/notes/{}'.format(test_file_part), headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. File exists')
        resp = await client.delete('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'File {} is successfully deleted'.format(test_file_2)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. File does not exist')
        test_file_part = test_file_4.split('.')[0]
        resp = await client.delete('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'File {} does not exist'.format(test_file_4)
        assert not os.path.exists('{}/{}'.format(test_folder, test_file_4))
        logging.info('Test is succeeded')

    async def test_signup(self, client, prepare_data):
        client, handler = tuple(client)
        test_email = 'user4@test.su'
        db = DataBase()
        db_session = db.create_session()

        logging.info('Test request. Method not allowed')
        resp = await client.put('/signup', json={
            'email': test_email,
            'password': '4test1234',
            'confirm_password': '4test1234',
            'name': 'User4',
        })
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User does not exist')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': '4test1234',
            'confirm_password': '4test1234',
            'name': 'User4',
        })
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'User with email {} is successfully registered'.format(test_email)
        assert db_session.query(db.User).filter_by(email=test_email).first()
        logging.info('Test is succeeded')

        logging.info('Test request. Email is not set')
        resp = await client.post('/signup', json={
            'password': '4test1234',
            'confirm_password': '4test1234',
            'name': 'User4',
        })
        assert resp.status == 400
        assert await resp.text() == 'Email is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Invalid email format')
        resp = await client.post('/signup', json={
            'email': 'user4',
            'password': '4test1234',
            'confirm_password': '4test1234',
            'name': 'User4',
        })
        assert resp.status == 400
        assert await resp.text() == 'Invalid email format'
        logging.info('Test is succeeded')

        logging.info('Test request. Password is not set')
        resp = await client.post('/signup', json={'email': test_email, 'name': 'User4'})
        assert resp.status == 400
        assert await resp.text() == 'Password is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Invalid password')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': 'test',
            'confirm_password': '4test1234',
            'name': 'User4',
        })
        assert resp.status == 400
        assert await resp.text() == \
            'Invalid password. Password should contain letters, digits and will be 8 to 50 characters long'
        logging.info('Test is succeeded')

        logging.info('Test request. Password is not confirmed')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': '4test1234',
            'name': 'User4',
        })
        assert resp.status == 400
        assert await resp.text() == 'Please, repeat the password'
        logging.info('Test is succeeded')

        logging.info('Test request. Passwords are not match')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': '4test1234',
            'confirm_password': '4test12345',
            'name': 'User4',
        })
        assert resp.status == 400
        assert await resp.text() == 'Passwords are not match'
        logging.info('Test is succeeded')

        logging.info('Test request. Name is not set')
        resp = await client.post('/signup', json={
            'email': test_email,
            'password': '4test1234',
            'confirm_password': '4test1234',
        })
        assert resp.status == 400
        assert await resp.text() == 'Name is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. User exists')
        test_email_exists = 'user1@test.su'
        resp = await client.post('/signup', json={
            'email': test_email_exists,
            'password': '4test1234',
            'confirm_password': '4test1234',
            'name': 'User4',
        })
        assert resp.status == 400
        assert await resp.text() == 'User with email {} already exists'.format(test_email_exists)
        logging.info('Test is succeeded')

    async def test_signin(self, client, prepare_data):
        client, handler = tuple(client)
        test_email = 'user1@test.su'
        db = DataBase()
        db_session = db.create_session()
        test_user = db_session.query(db.User).filter_by(email=test_email).first()

        logging.info('Test request. Method not allowed')
        resp = await client.put('/signin', json={'email': test_email, 'password': '1test1234'})
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User exists')
        resp = await client.post('/signin', json={'email': test_email, 'password': '1test1234'})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully signed in system'
        assert db_session.query(db.Session).filter_by(user=test_user).first()
        assert len(db_session.query(db.Session).filter_by(user=test_user).all()) > 1
        logging.info('Test is succeeded')

        logging.info('Test request. Email is not set')
        resp = await client.post('/signin', json={'password': '1test1234'})
        assert resp.status == 400
        assert await resp.text() == 'Email is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Invalid email format')
        resp = await client.post('/signin', json={'email': 'user1', 'password': '1test1234'})
        assert resp.status == 400
        assert await resp.text() == 'Invalid email format'
        logging.info('Test is succeeded')

        logging.info('Test request. Password is not set')
        resp = await client.post('/signin', json={'email': test_email})
        assert resp.status == 400
        assert await resp.text() == 'Password is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Invalid password')
        resp = await client.post('/signin', json={'email': test_email, 'password': 'test'})
        assert resp.status == 400
        assert await resp.text() == 'Invalid login or password'
        logging.info('Test is succeeded')

        logging.info('Test request. User does not exist')
        resp = await client.post('/signin', json={'email': 'user4@test.su', 'password': 'test'})
        assert resp.status == 400
        assert await resp.text() == 'Invalid login or password'
        logging.info('Test is succeeded')

    async def test_logout(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        db = DataBase()
        db_session = db.create_session()

        logging.info('Test request. Method not allowed')
        resp = await client.put('/logout')
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.get('/logout')
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. User is logged in')
        resp = await client.get('/logout', headers={'Authorization': session_denied.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully logged out'
        assert not db_session.query(db.Session).filter_by(uuid=session_denied.uuid).first()
        logging.info('Test is succeeded')

    async def test_add_method(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_method_name = 'test_method_2'
        db = DataBase()
        db_session = db.create_session()

        logging.info('Test request. Method not allowed')
        resp = await client.get('/method/{}'.format(test_method_name))
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.put('/method/{}'.format(test_method_name))
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.put('/method/{}'.format(test_method_name), headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.put('/method/{}'.format(test_method_name), headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.put('/method/{}'.format(test_method_name), headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method does not exist')
        resp = await client.put('/method/{}'.format(test_method_name), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully added method {}'.format(test_method_name)
        assert db_session.query(db.Method).filter_by(name=test_method_name).first()
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method exists')
        test_method_name_exists = 'test_method_1'
        resp = await client.put(
            '/method/{}'.format(test_method_name_exists), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method {} already exists'.format(test_method_name_exists)
        logging.info('Test is succeeded')

    async def test_delete_method(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_method_name = 'test_method_1'
        db = DataBase()
        db_session = db.create_session()

        logging.info('Test request. Method not allowed')
        resp = await client.get('/method/{}'.format(test_method_name))
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.delete('/method/{}'.format(test_method_name))
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.delete('/method/{}'.format(test_method_name), headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.delete(
            '/method/{}'.format(test_method_name), headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.delete(
            '/method/{}'.format(test_method_name), headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method exists')
        resp = await client.delete(
            '/method/{}'.format(test_method_name), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully deleted method {}'.format(test_method_name)
        assert not db_session.query(db.Method).filter_by(name=test_method_name).first()
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method does not exist')
        resp = await client.delete(
            '/method/{}'.format(test_method_name), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method {} is not found'.format(test_method_name)
        logging.info('Test is succeeded')

    async def test_add_role(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_role_name = 'test_role_4'
        db = DataBase()
        db_session = db.create_session()

        logging.info('Test request. Method not allowed')
        resp = await client.get('/role/{}'.format(test_role_name))
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.put('/role/{}'.format(test_role_name))
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.put('/role/{}', headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.put('/role/{}'.format(test_role_name), headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.put('/role/{}'.format(test_role_name), headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role does not exist')
        resp = await client.put('/role/{}'.format(test_role_name), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully added role {}'.format(test_role_name)
        assert db_session.query(db.Role).filter_by(name=test_role_name).first()
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role exists')
        test_role_name_exists = 'test_role_1'
        resp = await client.put(
            '/role/{}'.format(test_role_name_exists), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Role {} already exists'.format(test_role_name_exists)
        logging.info('Test is succeeded')

    async def test_delete_role(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_role_name = 'test_role_3'
        db = DataBase()
        db_session = db.create_session()

        logging.info('Test request. Method not allowed')
        resp = await client.get('/role/{}'.format(test_role_name))
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.delete('/role/{}'.format(test_role_name))
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.delete('/role/{}'.format(test_role_name), headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.delete('/role/{}'.format(test_role_name), headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.delete('/role/{}'.format(test_role_name), headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role exists. Role without user')
        resp = await client.delete('/role/{}'.format(test_role_name), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully deleted role {}'.format(test_role_name)
        assert not db_session.query(db.Role).filter_by(name=test_role_name).first()
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role exists. Role with user')
        resp = await client.delete('/role/{}'.format('test_role_2'), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == "You can't delete role with users"
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role does not exist')
        resp = await client.delete('/role/{}'.format(test_role_name), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Role {} is not found'.format(test_role_name)
        logging.info('Test is succeeded')

    async def test_add_method_to_role(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_method_name = 'test_method_1'
        test_role_name = 'test_role_1'
        db = DataBase()
        db_session = db.create_session()
        test_method = db_session.query(db.Method).filter_by(name=test_method_name).first()
        test_role = db_session.query(db.Role).filter_by(name=test_role_name).first()

        logging.info('Test request. Method not allowed')
        resp = await client.get('/add_method_to_role', json={'method': test_method_name, 'role': test_role_name})
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.post('/add_method_to_role', json={'method': test_method_name, 'role': test_role_name})
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.post(
            '/add_method_to_role',
            json={'method': test_method_name, 'role': test_role_name},
            headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.post(
            '/add_method_to_role',
            json={'method': test_method_name, 'role': test_role_name},
            headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.post(
            '/add_method_to_role',
            json={'method': test_method_name, 'role': test_role_name},
            headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method name is not set')
        resp = await client.post(
            '/add_method_to_role', json={'role': test_role_name}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method name is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role name is not set')
        resp = await client.post(
            '/add_method_to_role', json={'method': test_method_name}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Role name is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method does not exist')
        test_method_name_not_exists = 'test_method_2'
        resp = await client.post(
            '/add_method_to_role',
            json={'method': test_method_name_not_exists, 'role': test_role_name},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method {} is not found'.format(test_method_name_not_exists)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role does not exist')
        test_role_name_not_exists = 'test_role_4'
        resp = await client.post(
            '/add_method_to_role',
            json={'method': test_method_name, 'role': test_role_name_not_exists},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Role {} is not found'.format(test_role_name_not_exists)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method is already added to role')
        test_role_name_with_method = 'test_role_2'
        resp = await client.post(
            '/add_method_to_role',
            json={'method': test_method_name, 'role': test_role_name_with_method},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method {} already exists in role {}'.format(
            test_method_name, test_role_name_with_method)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method is not added to role')
        resp = await client.post(
            '/add_method_to_role',
            json={'method': test_method_name, 'role': test_role_name},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully added method {} to role {}'.format(
            test_method_name, test_role_name)
        assert db_session.query(db.MethodRole).filter_by(method_id=test_method.id, role_id=test_role.id).first()
        logging.info('Test is succeeded')

    async def test_delete_method_from_role(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_method_name = 'test_method_1'
        test_role_name = 'test_role_2'
        db = DataBase()
        db_session = db.create_session()
        test_method = db_session.query(db.Method).filter_by(name=test_method_name).first()
        test_role = db_session.query(db.Role).filter_by(name=test_role_name).first()

        logging.info('Test request. Method not allowed')
        resp = await client.get('/delete_method_from_role', json={'method': test_method_name, 'role': test_role_name})
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.post('/delete_method_from_role', json={'method': test_method_name, 'role': test_role_name})
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.post(
            '/delete_method_from_role',
            json={'method': test_method_name, 'role': test_role_name},
            headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.post(
            '/delete_method_from_role',
            json={'method': test_method_name, 'role': test_role_name},
            headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.post(
            '/delete_method_from_role',
            json={'method': test_method_name, 'role': test_role_name},
            headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method name is not set')
        resp = await client.post(
            '/delete_method_from_role', json={'role': test_role_name}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method name is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role name is not set')
        resp = await client.post(
            '/delete_method_from_role',
            json={'method': test_method_name},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Role name is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method does not exist')
        test_method_name_not_exists = 'test_method_2'
        resp = await client.post(
            '/delete_method_from_role',
            json={'method': test_method_name_not_exists, 'role': test_role_name},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method {} is not found'.format(test_method_name_not_exists)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role does not exist')
        test_role_name_not_exists = 'test_role_4'
        resp = await client.post(
            '/delete_method_from_role',
            json={'method': test_method_name, 'role': test_role_name_not_exists},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Role {} is not found'.format(test_role_name_not_exists)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method is not found in role')
        test_role_name_without_method = 'test_role_1'
        resp = await client.post(
            '/delete_method_from_role',
            json={'method': test_method_name, 'role': test_role_name_without_method},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method {} is not found in role {}'.format(
            test_method_name, test_role_name_without_method)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method is added to role')
        resp = await client.post(
            '/delete_method_from_role',
            json={'method': test_method_name, 'role': test_role_name},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'You successfully deleted method {} from role {}'.format(
            test_method_name, test_role_name)
        assert not db_session.query(db.MethodRole).filter_by(method_id=test_method.id, role_id=test_role.id).first()
        logging.info('Test is succeeded')

    async def test_change_shared_prop(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_method_name = 'test_method_1'
        db = DataBase()
        db_session = db.create_session()

        logging.info('Test request. Method not allowed')
        resp = await client.get('/change_shared_prop', json={'method': test_method_name, 'value': True})
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.post('/change_shared_prop', json={'method': test_method_name, 'value': True})
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.post(
            '/change_shared_prop', json={'method': test_method_name, 'value': True}, headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.post(
            '/change_shared_prop',
            json={'method': test_method_name, 'value': True},
            headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.post(
            '/change_shared_prop',
            json={'method': test_method_name, 'value': True},
            headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method name is not set')
        resp = await client.post(
            '/change_shared_prop', json={'value': True}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method name is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Value is not set')
        resp = await client.post(
            '/change_shared_prop', json={'method': test_method_name}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Value is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Value is not boolean')
        resp = await client.post(
            '/change_shared_prop',
            json={'method': test_method_name, 'value': 'test'},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Value should be boolean'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method does not exist')
        test_method_name_not_exists = 'test_method_2'
        resp = await client.post(
            '/change_shared_prop',
            json={'method': test_method_name_not_exists, 'value': True},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Method {} is not found'.format(test_method_name_not_exists)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Method exists')
        resp = await client.post(
            '/change_shared_prop',
            json={'method': test_method_name, 'value': True},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == \
            'You successfully changed shared property of method {}. Property is enabled'.format(test_method_name)
        test_method = db_session.query(db.Method).filter_by(name=test_method_name).first()
        assert test_method.shared
        logging.info('Test is succeeded')

    async def test_change_user_role(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        test_email = 'user1@test.su'
        test_role_name = 'test_role_2'
        db = DataBase()
        db_session = db.create_session()

        logging.info('Test request. Method not allowed')
        resp = await client.get('/change_user_role', json={'email': test_email, 'role': test_role_name})
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.post('/change_user_role', json={'email': test_email, 'role': test_role_name})
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.post(
            '/change_user_role', json={'email': test_email, 'role': test_role_name}, headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.post(
            '/change_user_role',
            json={'email': test_email, 'role': test_role_name},
            headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.post(
            '/change_user_role',
            json={'email': test_email, 'role': test_role_name},
            headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Email is not set')
        resp = await client.post(
            '/change_user_role', json={'role': test_role_name}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Email is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role name is not set')
        resp = await client.post(
            '/change_user_role', json={'email': test_email}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Role name is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. User does not exist')
        test_email_not_exists = 'user4@test.su'
        resp = await client.post(
            '/change_user_role',
            json={'email': test_email_not_exists, 'role': test_role_name},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'User with email {} is not found'.format(test_email_not_exists)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Role does not exist')
        test_role_name_not_exists = 'test_role_4'
        resp = await client.post(
            '/change_user_role',
            json={'email': test_email, 'role': test_role_name_not_exists},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Role {} is not found'.format(test_role_name_not_exists)
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. User and role exist')
        resp = await client.post(
            '/change_user_role',
            json={'email': test_email, 'role': test_role_name},
            headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == \
            'You successfully changed role of user with email {}. New role is {}'.format(test_email, test_role_name)
        test_user = db_session.query(db.User).filter_by(email=test_email).first()
        test_role = db_session.query(db.Role).filter_by(name=test_role_name).first()
        assert test_user.role_id == test_role.id
        logging.info('Test is succeeded')

    async def test_change_file_dir(self, client, prepare_data):
        client, handler = tuple(client)
        session_denied, session_allowed, session_no_role = tuple(prepare_data)
        new_test_folder = '../test_folder_2'

        logging.info('Test request. Method not allowed')
        resp = await client.get('/change_file_dir', json={'path': new_test_folder})
        assert resp.status == 405
        logging.info('Test is succeeded')

        logging.info('Test request. User is not logged in')
        resp = await client.post('/change_file_dir', json={'path': new_test_folder})
        assert resp.status == 401
        assert await resp.text() == 'Unauthorized request'
        logging.info('Test is succeeded')

        logging.info('Test request. Session expired')
        resp = await client.post('/change_file_dir', json={'path': new_test_folder}, headers={'Authorization': 'test'})
        assert resp.status == 401
        assert await resp.text() == 'Session expired. Please, sign in again'
        logging.info('Test is succeeded')

        logging.info('Test request. Access denied')
        resp = await client.post(
            '/change_file_dir', json={'path': new_test_folder}, headers={'Authorization': session_denied.uuid})
        assert resp.status == 403
        assert await resp.text() == 'Access denied'
        logging.info('Test is succeeded')

        logging.info('Test request. User without role')
        resp = await client.post(
            '/change_file_dir', json={'path': new_test_folder}, headers={'Authorization': session_no_role.uuid})
        assert resp.status == 403
        assert await resp.text() == 'User is not attached to role'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Directory path is not set')
        resp = await client.post('/change_file_dir', json={}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 400
        assert await resp.text() == 'Directory path is not set'
        logging.info('Test is succeeded')

        logging.info('Test request. Access allowed. Directory path is set')
        resp = await client.post(
            '/change_file_dir', json={'path': new_test_folder}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == \
            'You successfully changed working directory path. New path is {}'.format(new_test_folder)
        assert handler.file_service.path == new_test_folder
        logging.info('Test is succeeded')
