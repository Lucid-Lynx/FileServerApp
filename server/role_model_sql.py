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

    @staticmethod
    def role_model(func):

        def wrapper(*args, **kwargs) -> web.Response:
            request = args[1]
            session_id = request.headers.get('Authorization')

            if not session_id:
                raise web.HTTPForbidden()

            try:
                with closing(psycopg2.connect(**conn_params)) as conn:
                    with conn.cursor(cursor_factory=DictCursor) as cursor:
                        cursor.execute(sql.SQL(
                            'SELECT * FROM public."Session" AS S JOIN public."User" AS U '
                            'ON S."user_id" = U."Id" WHERE "UUID" = \'{}\''.format(session_id)))
                        session = cursor.fetchone()
                        assert session, 'Session expired. Please, sign in again'
                        cursor.execute(sql.SQL('SELECT * FROM public."Method" WHERE "Name" = \'{}\''.format(
                            func.__name__)))
                        method = cursor.fetchone()

                        if method and not method['Shared']:
                            cursor.execute(sql.SQL(
                                'SELECT * FROM public."Role" AS R JOIN public."MethodRole" AS MR '
                                'ON R."Id" = MR."role_id" WHERE R."Id" = \'{}\' '
                                'AND MR."method_id" = \'{}\''.format(session['role_id'], method['Id'])))
                            relation = cursor.fetchone()
                            assert relation, 'Access denied'

                return func(*args, **kwargs)

            except AssertionError as err:
                return web.json_response(data={
                    'status': 'error',
                    'message': '{}'.format(err),
                })

        return wrapper
