# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import re
import os
import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor
from contextlib import closing
from datetime import datetime, timedelta
from aiohttp import web
from uuid import uuid4
from server.crypto import HashAPI

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
    """Class with static methods for working with users via SQL.

    """

    @staticmethod
    def authorized(func):
        """Decorator for checking user authorization.

        Args:
            func (function): Method for decoration.

        Returns:
            Function, which wrap method for decoration.

        """

        def wrapper(*args, **kwargs) -> web.Response:
            """Wrap decorated method.

            Args:
                *args (tuple): Tuple with nameless arguments;
                **kwargs (dict): Dict with named arguments.

            Returns:
                Result of called wrapped method.

            Raises:
                HTTPUnauthorized: 401 HTTP error, if user session is expired or not found.

            """

            request = args[1]
            session_id = request.headers.get('Authorization')

            if not session_id:
                raise web.HTTPUnauthorized(text='Unauthorized request')

            with closing(psycopg2.connect(**conn_params)) as conn:
                with conn.cursor(cursor_factory=DictCursor) as cursor:
                    cursor.execute(sql.SQL(f'SELECT * FROM public."Session" WHERE "UUID" = {sql.Literal(session_id)}'))
                    session = cursor.fetchone()

                    if not session:
                        raise web.HTTPUnauthorized(text='Session expired. Please, sign in again')

                    if session['Expiration Date'] < datetime.now():
                        cursor.execute(
                            sql.SQL(f'DELETE FROM public."Session" WHERE "Id" = {sql.Literal(session["Id"])}'))
                        conn.commit()
                        raise web.HTTPUnauthorized(text='Session expired. Please, sign in again')

                    kwargs.update(user_id=session['user_id'])

            return func(*args, **kwargs)

        return wrapper

    @staticmethod
    def signup(**kwargs):
        """Sign up new user.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                email (str): user's email. Required;
                password (str): user's password. Required letters and numbers. Quantity of symbols > 8 and < 50.
                Required;
                confirm_password (str): password confirmation. Must match with password. Required;
                name (str): user's first name. Required;
                surname (str): user's last name. Optional. Required.

        Raises:
            ValueError: if at least one of required parameters in kwargs is not set, email or password format is
            invalid, passwords are not match;
            SystemError: user with set email exists.

        """

        email = kwargs.get('email')
        password = kwargs.get('password')
        confirm_password = kwargs.get('confirm_password')
        name = kwargs.get('name')
        surname = kwargs.get('surname')

        if not email or not (email := email.strip()):
            raise ValueError('Email is not set')

        if not password or not (password := password.strip()):
            raise ValueError('Password is not set')

        if not confirm_password or not (confirm_password := confirm_password.strip()):
            raise ValueError('Please, repeat the password')

        if not name or not (name := name.strip()):
            raise ValueError('Name is not set')

        if not EMAIL_REGEX.match(email):
            raise ValueError('Invalid email format')

        if not PASSWORD_REGEX.match(password):
            raise ValueError(
                'Invalid password. Password should contain letters, digits and will be 8 to 50 characters long')

        if password != confirm_password:
            raise ValueError('Passwords are not match')

        if surname:
            surname = surname.strip()

        hashed_password = HashAPI.hash_sha512(password)

        with closing(psycopg2.connect(**conn_params)) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute(sql.SQL(f'SELECT * FROM public."User" WHERE "Email" = {sql.Literal(email)}'))
                existed_user = cursor.fetchone()

                if existed_user:
                    raise SystemError(f'User with email {email} already exists')

                cursor.execute(sql.SQL(f'SELECT * FROM public."Role" WHERE "Name" = {sql.Literal("visitor")}'))
                role_visitor = cursor.fetchone()
                columns = ("Create Date", "Email", "Password", "Name", "Surname", "role_id")
                values = (datetime.strftime(datetime.now(), dt_format), email, hashed_password, name, surname,
                          role_visitor['Id'])
                cursor.execute(sql.SQL(
                    f'INSERT INTO public."User" ({sql.SQL(", ").join(map(sql.Identifier, columns))}) '
                    f'VALUES({sql.SQL(", ").join(map(sql.Literal, values))})'))
                conn.commit()

    @staticmethod
    def signin(**kwargs) -> str:
        """Sign in user.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                email (str): user's email. Required;
                password (str): user's password. Required.

        Returns:
            Str with session UUID.

        Raises:
            ValueError: if at least one of required parameters in kwargs is not set, email format is invalid;
            PermissionError: incorrect login or password.

        """

        email = kwargs.get('email')
        password = kwargs.get('password')

        if not email or not (email := email.strip()):
            raise ValueError('Email is not set')

        if not password or not (password := password.strip()):
            raise ValueError('Password is not set')

        if not EMAIL_REGEX.match(email):
            raise ValueError('Invalid email format')

        hashed_password = HashAPI.hash_sha512(password)
        uuid_str = str(uuid4())

        with closing(psycopg2.connect(**conn_params)) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute(sql.SQL(f'SELECT * FROM public."User" WHERE "Email" = {sql.Literal(email)}'))
                user = cursor.fetchone()

                if not user or hashed_password != user['Password']:
                    raise PermissionError('Incorrect login or password')

                cursor.execute(sql.SQL(f'SELECT * FROM public."Session" WHERE "user_id" = {sql.Literal(user["Id"])}'))
                user_session = cursor.fetchone()

                if user_session and user_session['Expiration Date'] >= datetime.now():
                    return user_session['UUID']

                elif user_session:
                    cursor.execute(
                        sql.SQL(f'DELETE FROM public."Session" WHERE "Id" = {sql.Literal(user_session["Id"])}'))

                columns = ("Create Date", "UUID", "Expiration Date", "user_id")
                values = (datetime.strftime(datetime.now(), dt_format), str(uuid_str),
                          datetime.strftime(datetime.now() + timedelta(
                              hours=int(os.environ['SESSION_DURATION_HOURS'])), dt_format), user['Id'])
                cursor.execute(sql.SQL(
                    f'INSERT INTO public."Session" ({sql.SQL(", ").join(map(sql.Identifier, columns))}) '
                    f'VALUES ({sql.SQL(", ").join(map(sql.Literal, values))})'))
                cursor.execute(sql.SQL(
                    f'UPDATE public."User" SET "Last Login Date" = '
                    f'{sql.Literal(datetime.strftime(datetime.now(), dt_format))} '
                    f'WHERE "Id" = {sql.Literal(user["Id"])}'))
                conn.commit()
        
        return uuid_str

    @staticmethod
    def logout(session_id: str):
        """Logout user.

        Args:
            session_id (str): session UUID.

        """

        with closing(psycopg2.connect(**conn_params)) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute(sql.SQL(f'DELETE FROM public."Session" WHERE "UUID" = {sql.Literal(session_id)}'))
                conn.commit()
