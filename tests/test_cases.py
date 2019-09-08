import os
import pytest
import json
from aiohttp import web
from server.handler import Handler

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

    return loop.run_until_complete(aiohttp_client(app))


class TestSuite:

    async def test_connection(self, client):
        resp = await client.get('/')
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'

    async def test_get_files(self, client):
        resp = await client.get('/notes')
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

    async def test_get_file_info(self, client):
        test_file_part = test_file_1.split('.')[0]
        resp = await client.get('/notes/{}'.format(test_file_part))
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists(filename)
        assert filename == test_file_1
        content = result.get('data').get('content')
        assert content == test_content

    async def test_create_file(self, client):
        resp = await client.post('/notes', json={'content': test_content})
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        filename = result.get('data').get('name')
        assert os.path.exists(filename)

    async def test_delete_file(self, client):
        test_file_part = test_file_2.split('.')[0]
        resp = await client.delete('/notes/{}'.format(test_file_part))
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'success'
        assert result.get('message') == 'File {} is successfully deleted'.format(test_file_part)

    async def test_get_file_info_not_exists(self, client):
        test_file_part = test_file_3.split('.')[0]
        resp = await client.get('/notes/{}'.format(test_file_part))
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'error'
        assert result.get('message') == 'File {} is not exists'.format(test_file_3)
        assert not os.path.exists(test_file_3)

    async def test_delete_file_not_exists(self, client):
        test_file_part = test_file_3.split('.')[0]
        resp = await client.delete('/notes/{}'.format(test_file_part))
        assert resp.status == 200
        result = json.loads(await resp.text())
        assert result.get('status') == 'error'
        assert result.get('message') == 'File {} is not exists'.format(test_file_3)
        assert not os.path.exists(test_file_3)

