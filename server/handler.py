import json
from aiohttp import web
from server.file_service import FileService


class Handler:
    """Aiohttp handler with coroutines.

    """

    def __init__(self):
        pass

    async def handle(self, request: web.Request) -> web.Response:
        """Basic coroutine for connection testing.

        Args:
            request (Request): aiohttp request.

        Returns:
            Response: JSON response with status.

        """

        data = {
            'status': 'success'
        }
        return web.json_response(data)

    async def get_files(self, request: web.Request) -> web.Response:
        """Coroutine for getting info about all files in working directory.

        Args:
            request (Request): aiohttp request.

        Returns:
            Response: JSON response with success status and data or error status and error message.

        """

        return web.json_response(data={
            'status': 'success',
            'data': FileService.get_files(),
        })

    async def get_file_info(self, request: web.Request) -> web.Response:
        """Coroutine for getting full info about file in working directory.

        Args:
            request (Request): aiohttp request, contains filename.

        Returns:
            Response: JSON response with success status and data or error status and error message.

        """

        filename = request.match_info['filename']

        try:
            return web.json_response(data={
                'status': 'success',
                'data': FileService.get_file_data(filename),
            })

        except AssertionError as err:
            return web.json_response(data={
                'status': 'error',
                'message': '{}'.format(err),
            })

    async def create_file(self, request: web.Request) -> web.Response:
        """Coroutine for creating file.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {"content": "content string"}.

        Returns:
            Response: JSON response with success status and data or error status and error message.

        """

        result = ''
        stream = request.content

        while not stream.at_eof():
            line = await stream.read()
            result += line.decode('utf-8')

        try:
            data = json.loads(result)
            return web.json_response(data={
                'status': 'success',
                'data': FileService.create_file(data.get('content'))
            })

        except ValueError as err:
            return web.json_response(data={
                'status': 'error',
                'message': '{}'.format(err),
            })

    async def delete_file(self, request: web.Request) -> web.Response:
        """Coroutine for deleting file.

        Args:
            request (Request): aiohttp request, contains filename.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        """

        filename = request.match_info['filename']

        try:
            FileService.delete_file(filename)
            return web.json_response(data={
                'status': 'success',
                'message': 'File {} is successfully deleted'.format(filename),
            })

        except AssertionError as err:
            return web.json_response(data={
                'status': 'error',
                'message': '{}'.format(err),
            })

