import re
import os
import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor
from contextlib import closing
from datetime import datetime, timedelta
from aiohttp import web
from uuid import uuid4
from .crypto import CryptoAPI

EMAIL_REGEX = re.compile(r'[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}$')
PASSWORD_REGEX = re.compile(r'^\w{8,50}$')

conn_params = {
        'dbname': os.environ['DB_NAME'],
        'user': os.environ['DB_USER'],
        'password': os.environ['DB_PASSWORD'],
        'host': os.environ['DB_HOST']
    }
dt_format = os.environ['DATE_FORMAT']


class UsersSQLAPI:

    @staticmethod
    def authorized(func):

        def wrapper(*args, **kwargs) -> web.Response:
            request = args[1]
            session_id = request.headers.get('Authorization')

            if not session_id:
                raise web.HTTPUnauthorized(text='Unauthorized request')

            with closing(psycopg2.connect(**conn_params)) as conn:
                with conn.cursor(cursor_factory=DictCursor) as cursor:
                    cursor.execute(sql.SQL('SELECT * FROM public."Session" WHERE "UUID" = {}').format(
                        sql.Literal(session_id)))
                    session = cursor.fetchone()

                    if not session:
                        raise web.HTTPUnauthorized(text='Session expired. Please, sign in again')

                    if session['Expiration Date'] < datetime.now():
                        cursor.execute(
                            sql.SQL('DELETE FROM public."Session" WHERE "Id" = {}').format(sql.Literal(session['Id'])))
                        conn.commit()
                        raise web.HTTPUnauthorized(text='Session expired. Please, sign in again')

            return func(*args, **kwargs)

        return wrapper

    @staticmethod
    def signup(**kwargs):
        email = kwargs.get('email')
        password = kwargs.get('password')
        confirm_password = kwargs.get('confirm_password')
        name = kwargs.get('name')
        surname = kwargs.get('surname')

        assert email and (email := email.strip()), 'Email is not set'
        assert password and (password := password.strip()), 'Password is not set'
        assert confirm_password and (confirm_password := confirm_password.strip()), 'Please, repeat the password'
        assert name and (name := name.strip()), 'Name is not set'
        assert EMAIL_REGEX.match(email), 'Invalid email format'
        assert PASSWORD_REGEX.match(password), \
            'Invalid password. Password should contain letters, digits and will be 8 to 50 characters long'
        assert password == confirm_password, 'Passwords are not match'

        if surname:
            surname = surname.strip()

        hashed_password = CryptoAPI.hash_sha512(password)

        with closing(psycopg2.connect(**conn_params)) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute(sql.SQL('SELECT * FROM public."User" WHERE "Email" = {}').format(sql.Literal(email)))
                existed_user = cursor.fetchone()
                assert not existed_user, 'User with email {} already exists'.format(email)
                cursor.execute(sql.SQL('SELECT * FROM public."Role" WHERE "Name" = {}').format(sql.Literal('visitor')))
                role_visitor = cursor.fetchone()
                columns = ("Create Date", "Email", "Password", "Name", "Surname", "role_id")
                values = (datetime.strftime(datetime.now(), dt_format), email, hashed_password, name, surname,
                          role_visitor['Id'])
                cursor.execute(sql.SQL(
                    'INSERT INTO public."User" ({}) VALUES({})').format(
                    sql.SQL(', ').join(map(sql.Identifier, columns)),
                        sql.SQL(', ').join(map(sql.Literal, values))))
                conn.commit()

    @staticmethod
    def signin(**kwargs) -> str:
        email = kwargs.get('email')
        password = kwargs.get('password')

        assert email and (email := email.strip()), 'Email is not set'
        assert password and (password := password.strip()), 'Password is not set'
        assert EMAIL_REGEX.match(email), 'Invalid email format'

        hashed_password = CryptoAPI.hash_sha512(password)
        uuid_str = str(uuid4())

        with closing(psycopg2.connect(**conn_params)) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute(sql.SQL('SELECT * FROM public."User" WHERE "Email" = {}').format(sql.Literal(email)))
                user = cursor.fetchone()
                assert user and hashed_password == user['Password'], 'Invalid login or password'.format(email)
                columns = ("Create Date", "UUID", "Expiration Date", "user_id")
                values = (datetime.strftime(datetime.now(), dt_format), str(uuid_str),
                          datetime.strftime(datetime.now() + timedelta(
                              hours=int(os.environ['SESSION_DURATION_HOURS'])), dt_format), user['Id'])
                cursor.execute(sql.SQL(
                    'INSERT INTO public."Session" ({}) VALUES ({})').format(
                        sql.SQL(', ').join(map(sql.Identifier, columns)),
                        sql.SQL(', ').join(map(sql.Literal, values))))
                cursor.execute(sql.SQL('UPDATE public."User" SET "Last Login Date" = {} WHERE "Id" = {}').format(
                    sql.Literal(datetime.strftime(datetime.now(), dt_format)), sql.Literal(user['Id'])))
                conn.commit()
        
        return uuid_str

    @staticmethod
    def logout(session_id: str):
        with closing(psycopg2.connect(**conn_params)) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute(sql.SQL('DELETE FROM public."Session" WHERE "UUID" = {}').format(
                    sql.Literal(session_id)))
                conn.commit()
