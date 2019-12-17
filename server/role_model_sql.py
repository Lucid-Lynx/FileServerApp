# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor
from contextlib import closing
from aiohttp import web

conn_params = {
        'dbname': os.environ['DB_NAME'],
        'user': os.environ['DB_USER'],
        'password': os.environ['DB_PASSWORD'],
        'host': os.environ['DB_HOST']
    }


class RoleModelSQL:
    """Class with static methods for working with role model via SQL.

    """

    @staticmethod
    def role_model(func):
        """Decorator for checking access permissions in role model.

        Args:
            func (function): Method for decoration.

        Returns:
            Function, which wrap method for decoration.

        """

        def wrapper(*args, **kwargs) -> web.Response:
            """Wrap decorated method.

            Args:
                *args (tuple): Tuple with nameless arguments,
                **kwargs (dict): Dict with named arguments.

            Returns:
                Result of called wrapped method.

            Raises:
                HTTPUnauthorized: 401 HTTP error, if user session is expired or not found,
                HTTPForbidden: 403 HTTP error, if access denied.

            """

            request = args[1]
            session_id = request.headers.get('Authorization')

            if not session_id:
                raise web.HTTPUnauthorized(text='Unauthorized request')

            with closing(psycopg2.connect(**conn_params)) as conn:
                with conn.cursor(cursor_factory=DictCursor) as cursor:
                    cursor.execute(sql.SQL(
                        'SELECT * FROM public."Session" AS S JOIN public."User" AS U '
                        'ON S."user_id" = U."Id" WHERE "UUID" = {}').format(sql.Literal(session_id)))
                    session = cursor.fetchone()

                    if not session:
                        raise web.HTTPUnauthorized(text='Session expired. Please, sign in again')

                    if not session.get('role_id'):
                        raise web.HTTPForbidden(text='User is not attached to role')

                    cursor.execute(sql.SQL('SELECT * FROM public."Method" WHERE "Name" = {}').format(
                        sql.Literal(func.__name__)))
                    method = cursor.fetchone()

                    if method and not method['Shared']:
                        cursor.execute(sql.SQL(
                            'SELECT * FROM public."Role" AS R JOIN public."MethodRole" AS MR '
                            'ON R."Id" = MR."role_id" WHERE R."Id" = {} AND MR."method_id" = {}').format(
                                sql.Literal(session['role_id']), sql.Literal(method['Id'])))
                        relation = cursor.fetchone()

                        if not relation:
                            raise web.HTTPForbidden(text='Access denied')

                return func(*args, **kwargs)

        return wrapper
