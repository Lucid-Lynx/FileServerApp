# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import json
from aiohttp import web
from queue import Queue
from distutils.util import strtobool
from server.file_service import FileService, FileServiceSigned
from server.file_loader import FileLoader, QueuedLoader
from server.users import UsersAPI
from server.role_model import RoleModel
from server.users_sql import UsersSQLAPI
from server.role_model_sql import RoleModelSQL


class Handler:
    """Aiohttp handler with coroutines.

    """

    def __init__(self, path: str):
        self.file_service = FileService(path=path)
        self.file_service_signed = FileServiceSigned(path=path)
        self.queue = Queue()

        for i in range(2):
            thread = QueuedLoader(self.queue)
            thread.start()

    async def handle(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Basic coroutine for connection testing.

        Args:
            request (Request): aiohttp request.

        Returns:
            Response: JSON response with status.

        """

        return web.json_response(data={
            'status': 'success'
        })

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def get_files(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for getting info about all files in working directory.

        Args:
            request (Request): aiohttp request.

        Returns:
            Response: JSON response with success status and data or error status and error message.

        """

        return web.json_response(data={
            'status': 'success',
            'data': self.file_service.get_files(),
        })

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def get_file_info(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for getting full info about file in working directory.

        Args:
            request (Request): aiohttp request, contains filename and is_signed parameters.

        Returns:
            Response: JSON response with success status and data or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        try:
            filename = request.rel_url.query['filename']
            is_signed = request.rel_url.query['is_signed']
            assert is_signed in ['true', 'false'], 'Is_signed is invalid'
            is_signed = strtobool(is_signed)

            if is_signed:
                file_service = self.file_service_signed
            else:
                file_service = self.file_service

            result = await file_service.get_file_data_async(filename, kwargs.get('user_id'))
            result.pop('user_id')
            result['size'] = '{} bytes'.format(result['size'])

            return web.json_response(data={
                'status': 'success',
                'data': result,
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

        except KeyError as err:
            raise web.HTTPBadRequest(text='Parameter {} is not set'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def create_file(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for creating file.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "content": "string. Content string. Optional",
                "security_level": "string. Security level. Optional. Default: low",
                "is_signed": "boolean. Sign or not created file. Optional. Default: false"
            }.

        Returns:
            Response: JSON response with success status and data or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        result = ''
        stream = request.content

        while not stream.at_eof():
            line = await stream.read()
            result += line.decode('utf-8')

        try:
            data = json.loads(result)
            is_signed = data.get('is_signed', False)
            assert isinstance(is_signed, bool), 'Is_signed should be boolean'

            if is_signed:
                file_service = self.file_service_signed
            else:
                file_service = self.file_service

            result = \
                await file_service.create_file(data.get('content'), data.get('security_level'), kwargs.get('user_id'))
            result.pop('user_id')
            result['size'] = '{} bytes'.format(result['size'])

            return web.json_response(data={
                'status': 'success',
                'data': result,
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def delete_file(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for deleting file.

        Args:
            request (Request): aiohttp request, contains filename.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        filename = request.match_info['filename']

        try:
            return web.json_response(data={
                'status': 'success',
                'message': 'File {} is successfully deleted'.format(self.file_service.delete_file(filename)),
            })

        except AssertionError as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def download_file(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for downloading files from working directory via threads.

        Args:
            request (Request): aiohttp request, contains filename and is_signed parameters.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        try:
            filename = request.rel_url.query['filename']
            is_signed = request.rel_url.query['is_signed']
            assert is_signed in ['true', 'false'], 'Is_signed is invalid'
            is_signed = strtobool(is_signed)

            thread = FileLoader(filename, kwargs.get('user_id'), is_signed)
            thread.start()
            thread.join()
            assert thread.state == 'finished', thread.message

            return web.json_response(data={
                'status': 'success',
                'message': thread.message,
            })

        except AssertionError as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

        except KeyError as err:
            raise web.HTTPBadRequest(text='Parameter {} is not set'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def download_file_queued(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for downloading files from working directory via queue.

        Args:
            request (Request): aiohttp request, contains filename and is_signed parameters.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        try:
            filename = request.rel_url.query['filename']
            is_signed = request.rel_url.query['is_signed']
            assert is_signed in ['true', 'false'], 'Is_signed is invalid'
            is_signed = strtobool(is_signed)
            self.queue.put({
                'filename': filename,
                'is_signed': is_signed,
                'user_id': kwargs.get('user_id'),
            })

            return web.json_response(data={
                'status': 'success',
                'message': 'Request for downloading file {}.{} is successfully added into queue'.format(
                    filename, self.file_service.extension),
            })

        except AssertionError as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

        except KeyError as err:
            raise web.HTTPBadRequest(text='Parameter {} is not set'.format(err))

    async def signup(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for signing up user.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "name": "string. User's first name. Required"
                "surname": "string. User's last name. Optional"
                "email": "string. User's email. Required",
                "password": "string. Required letters and numbers. Quantity of symbols > 8 and < 50. Required",
                "confirm_password": "string. Must match with password. Required"
            }.

        Returns:
            Response: JSON response with success status or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        result = ''
        stream = request.content

        while not stream.at_eof():
            line = await stream.read()
            result += line.decode('utf-8')

        try:
            data = json.loads(result)
            UsersAPI.signup(**data)
            # UsersSQLAPI.signup(**data)
            return web.json_response(data={
                'status': 'success',
                'message': 'User with email {} is successfully registered'.format(data.get('email')),
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    async def signin(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for signing in user.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "email": "string. User's email. Required",
                "password": "string. User's password. Required",
            }.

        Returns:
            Response: JSON response with success status, success message user's session UUID or error status and error
            message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

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
                'session_id': UsersAPI.signin(**data),
                # 'session_id': UsersSQLAPI.signin(**data),
                'message': 'You successfully signed in system',
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    async def logout(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for logout.

        Args:
            request (Request): aiohttp request, contains session_id.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPUnauthorized: 401 HTTP error, if user session is expired or not found.

        """

        session_id = request.headers.get('Authorization')

        if not session_id:
            raise web.HTTPUnauthorized(text='Unauthorized request')

        UsersAPI.logout(session_id)
        # UsersSQLAPI.logout(session_id)

        return web.json_response(data={
            'status': 'success',
            'message': 'You successfully logged out',
        })

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def add_method(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for adding method into role model.

        Args:
            request (Request): aiohttp request, contains method name.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        method_name = request.match_info['method_name']

        try:
            RoleModel.add_method(method_name)
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully added method {}'.format(method_name),
            })

        except AssertionError as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def delete_method(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for deleting method from role model.

        Args:
            request (Request): aiohttp request, contains method name.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        method_name = request.match_info['method_name']

        try:
            RoleModel.delete_method(method_name)
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully deleted method {}'.format(method_name),
            })

        except AssertionError as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def add_role(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for adding role into role method.

        Args:
            request (Request): aiohttp request, contains role name.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        role_name = request.match_info['role_name']

        try:
            RoleModel.add_role(role_name)
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully added role {}'.format(role_name),
            })

        except AssertionError as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def delete_role(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for deleting role from role method.

        Args:
            request (Request): aiohttp request, contains role name.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        role_name = request.match_info['role_name']

        try:
            RoleModel.delete_role(role_name)
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully deleted role {}'.format(role_name),
            })

        except AssertionError as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def add_method_to_role(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for adding method to role.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "method": "string. Method name. Required",
                "role": "string. Role name. Required",
            }.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        result = ''
        stream = request.content

        while not stream.at_eof():
            line = await stream.read()
            result += line.decode('utf-8')

        try:
            data = json.loads(result)
            RoleModel.add_method_to_role(**data)
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully added method {} to role {}'.format(data.get('method'), data.get('role')),
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def delete_method_from_role(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for deleting method from role.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "method": "string. Method name. Required",
                "role": "string. Role name. Required",
            }.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        result = ''
        stream = request.content

        while not stream.at_eof():
            line = await stream.read()
            result += line.decode('utf-8')

        try:
            data = json.loads(result)
            RoleModel.delete_method_from_role(**data)
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully deleted method {} from role {}'.format(
                    data.get('method'), data.get('role')),
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def change_shared_prop(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for changing shared property of method.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "method": "string. Method name. Required",
                "value": "boolean. Value of shared property. Required",
            }.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        result = ''
        stream = request.content

        while not stream.at_eof():
            line = await stream.read()
            result += line.decode('utf-8')

        try:
            data = json.loads(result)
            RoleModel.change_shared_prop(**data)
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully changed shared property of method {}. Property is {}'.format(
                    data.get('method'), 'enabled' if data.get('value') else 'disabled'),
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def change_user_role(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for setting new role to user.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "email": "string. User's email. Required",
                "role": "string. Role name. Required",
            }.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        result = ''
        stream = request.content

        while not stream.at_eof():
            line = await stream.read()
            result += line.decode('utf-8')

        try:
            data = json.loads(result)
            RoleModel.change_user_role(**data)
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully changed role of user with email {}. New role is {}'.format(
                    data.get('email'), data.get('role')),
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def change_file_dir(self, request: web.Request, *args, **kwargs) -> web.Response:
        """Coroutine for changing working directory with files.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "path": "string. Directory path. Required",
            }.

        Returns:
            Response: JSON response with success status and success message or error status and error message.

        Raises:
            HTTPBadRequest: 400 HTTP error, if error.

        """

        result = ''
        stream = request.content

        while not stream.at_eof():
            line = await stream.read()
            result += line.decode('utf-8')

        try:
            data = json.loads(result)
            path = data.get('path')
            assert path, 'Directory path is not set'
            self.file_service.path = path
            self.file_service_signed.path = path
            return web.json_response(data={
                'status': 'success',
                'message': 'You successfully changed working directory path. New path is {}'.format(data.get('path')),
            })

        except (AssertionError, ValueError) as err:
            raise web.HTTPBadRequest(text='{}'.format(err))
