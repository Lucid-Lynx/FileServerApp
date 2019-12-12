import json
from aiohttp import web
from .file_service import FileService
from .users import UsersAPI
from .role_model import RoleModel
from .users_sql import UsersSQLAPI
from .role_model_sql import RoleModelSQL


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

        return web.json_response(data={
            'status': 'success'
        })

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
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

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
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
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
    async def create_file(self, request: web.Request) -> web.Response:
        """Coroutine for creating file.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {"content": "content string. Optional"}.

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
            raise web.HTTPBadRequest(text='{}'.format(err))

    @UsersAPI.authorized
    @RoleModel.role_model
    # @UsersSQLAPI.authorized
    # @RoleModelSQL.role_model
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
            raise web.HTTPBadRequest(text='{}'.format(err))

    async def signup(self, request: web.Request) -> web.Response:
        """Coroutine for signing up user.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "name": "string. Required"
                "surname": "string. Optional"
                "email": "string. Required",
                "password": "string. Required letters and numbers. Quantity of symbols > 8 and < 50. Required",
                "confirm_password": "string. Must match with password. Required"
            }.

        Returns:
            Response: JSON response with success status or error status and error message.

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

    async def signin(self, request: web.Request) -> web.Response:
        """Coroutine for signing in user.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "email": "string. Required",
                "password": "string. Required",
            }.

        Returns:
            Response: JSON response with success status or error status and error message.

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

    async def logout(self, request: web.Request) -> web.Response:
        """Coroutine for logout.

        Args:
            request (Request): aiohttp request, contains session_id.

        Returns:
            Response: JSON response with success status.

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
    async def add_method(self, request: web.Request) -> web.Response:
        """Coroutine for adding method into role model.

        Args:
            request (Request): aiohttp request, contains method name.

        Returns:
            Response: JSON response with success status.

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
    async def delete_method(self, request: web.Request) -> web.Response:
        """Coroutine for deleting method from role model.

        Args:
            request (Request): aiohttp request, contains method name.

        Returns:
            Response: JSON response with success status.

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
    async def add_role(self, request: web.Request) -> web.Response:
        """Coroutine for adding role into role method.

        Args:
            request (Request): aiohttp request, contains role name.

        Returns:
            Response: JSON response with success status.

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
    async def delete_role(self, request: web.Request) -> web.Response:
        """Coroutine for deleting role from role method.

        Args:
            request (Request): aiohttp request, contains role name.

        Returns:
            Response: JSON response with success status.

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
    async def add_method_to_role(self, request: web.Request) -> web.Response:
        """Coroutine for adding method to role.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "method": "string. Required",
                "role": "string. Required",
            }.

        Returns:
            Response: JSON response with success status.

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
    async def delete_method_from_role(self, request: web.Request) -> web.Response:
        """Coroutine for deleting method from role.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "method": "string. Required",
                "role": "string. Required",
            }.

        Returns:
            Response: JSON response with success status.

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
    async def change_shared_prop(self, request: web.Request) -> web.Response:
        """Coroutine for changing shared property of method.

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "method": "string. Required",
                "value": "boolean. Required",
            }.

        Returns:
            Response: JSON response with success status.

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
    async def change_user_role(self, request: web.Request) -> web.Response:
        """Coroutine for setting new role to user .

        Args:
            request (Request): aiohttp request, contains JSON in body. JSON format:
            {
                "email": "string. Required",
                "role": "string. Required",
            }.

        Returns:
            Response: JSON response with success status.

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
