import os
import pytest
import json
import logging
from aiohttp import web
from server.handler import Handler
from server.database import DataBase

logger = logging.getLogger("Test Logger")

extension = 'txt'
test_folder = 'test_files'
test_file_1 = 'test_1.txt'
test_file_2 = 'test_2.txt'
test_file_3 = 'test_3.txt'
test_content = 'Test content/n'


def create_and_move_to_test_folder():
    os.chdir('..')
    if not os.path.exists(test_folder):
        os.mkdir(test_folder)
    os.chdir(test_folder)


def create_test_files():
    if not os.path.exists(test_file_1):
        with open(test_file_1, 'w') as file_handler:
            file_handler.write(test_content)

    if not os.path.exists(test_file_2):
        with open(test_file_2, 'w') as file_handler:
            file_handler.write(test_content)


@pytest.fixture
def client(loop, aiohttp_client):
    create_and_move_to_test_folder()
    create_test_files()

    handler = Handler()
    app = web.Application()
    app.router.add_get('/', handler.handle)
    app.router.add_get('/notes', handler.get_files)
    app.router.add_get('/notes/{filename}', handler.get_file_info)
    app.router.add_post('/notes', handler.create_file)
    app.router.add_delete('/notes/{filename}', handler.delete_file)
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

    return loop.run_until_complete(aiohttp_client(app))


@pytest.fixture(scope='class', autouse=True)
def prepare_data():
    logger.info('Prepare test data in database')
    db = DataBase()
    db_session = db.create_session()
    test_methods = db_session.query(db.Method).filter(db.Method.name.in_([
        'get_files', 'get_file_info', 'create_file', 'delete_file', 'add_method', 'delete_method', 'add_role',
        'delete_role', 'add_method_to_role', 'delete_method_from_role', 'change_shared_prop', 'change_user_role',
    ])).all()
    test_role_denied = db.Role('test_role_1')
    test_role_allowed = db.Role('test_role_2', methods=test_methods)
    session_denied = db.Session(db.User('user1@test.su', '1test1234', 'User1', role=test_role_denied))
    session_allowed = db.Session(db.User('user2@test.su', '2test1234', 'User2', role=test_role_allowed))
    db_session.add_all([session_denied, session_allowed])
    db_session.commit()

    yield session_denied, session_allowed

    logger.info('Clean test data in database')
    db_session.query(db.MethodRole).filter_by(role_id=test_role_allowed.id).delete()
    db_session.delete(test_role_denied)
    db_session.delete(test_role_allowed)
    db_session.commit()


class TestSuite:

    async def test_connection(self, client):
        resp = await client.get('/')
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'

    async def test_get_files(self, client, prepare_data):
        session_denied, session_allowed = tuple(prepare_data)

        resp = await client.get('/notes', headers={'Authorization': session_denied.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'error'
        assert result.get('message') == 'Access denied'

        resp = await client.get('/notes', headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        data = result.get('data')
        exists_files = list(filter(
            lambda file: file.get('name') in [test_file_1, test_file_2], data))
        exists_files = list(map(lambda file: file.get('name'), exists_files))
        assert len(exists_files) == 2
        assert test_file_1 in exists_files
        assert test_file_2 in exists_files
        assert not (test_file_3 in exists_files)

    async def test_get_file_info(self, client, prepare_data):
        session_denied, session_allowed = tuple(prepare_data)
        test_file_part = test_file_1.split('.')[0]

        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_denied.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'error'
        assert result.get('message') == 'Access denied'

        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists(filename)
        assert filename == test_file_1
        content = result.get('data').get('content')
        assert content == test_content

    async def test_create_file(self, client, prepare_data):
        session_denied, session_allowed = tuple(prepare_data)

        resp = await client.post(
            '/notes', json={'content': test_content}, headers={'Authorization': session_denied.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'error'
        assert result.get('message') == 'Access denied'

        resp = await client.post(
            '/notes', json={'content': test_content}, headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists(filename)

    async def test_delete_file(self, client, prepare_data):
        session_denied, session_allowed = tuple(prepare_data)
        test_file_part = test_file_2.split('.')[0]

        resp = await client.delete('/notes/{}'.format(test_file_part), headers={'Authorization': session_denied.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'error'
        assert result.get('message') == 'Access denied'

        resp = await client.delete('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'File {} is successfully deleted'.format(test_file_part)

    async def test_get_file_info_not_exists(self, client, prepare_data):
        session_denied, session_allowed = tuple(prepare_data)
        test_file_part = test_file_3.split('.')[0]

        resp = await client.get('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'error'
        assert result.get('message') == 'File {} is not exists'.format(test_file_3)
        assert not os.path.exists(test_file_3)

    async def test_delete_file_not_exists(self, client, prepare_data):
        session_denied, session_allowed = tuple(prepare_data)
        test_file_part = test_file_3.split('.')[0]

        resp = await client.delete('/notes/{}'.format(test_file_part), headers={'Authorization': session_allowed.uuid})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'error'
        assert result.get('message') == 'File {} is not exists'.format(test_file_3)
        assert not os.path.exists(test_file_3)
