# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import re
from datetime import datetime
from aiohttp import web
from server.db.database import DataBase
from server.crypto.crypto import HashAPI


EMAIL_REGEX = re.compile(r'[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}$')
PASSWORD_REGEX = re.compile(r'^\w{8,50}$')


class UsersAPI:
    """Class with static methods for working with users via ORM.

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

            db = DataBase()
            db_session = db.create_session()
            session = db_session.query(db.Session).filter_by(uuid=session_id).first()

            if not session:
                raise web.HTTPUnauthorized(text='Session expired. Please, sign in again')

            if session.exp_dt < datetime.now():
                db_session.delete(session)
                db_session.commit()
                raise web.HTTPUnauthorized(text='Session expired. Please, sign in again')

            kwargs.update(user_id=session.user_id)

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

        db = DataBase()
        db_session = db.create_session()
        existed_user = db_session.query(db.User).filter_by(email=email).first()

        if existed_user:
            raise SystemError(f'User with email {email} already exists')

        role_visitor = db_session.query(db.Role).filter_by(name="visitor").first()
        db_session.add(db.User(email, hashed_password, name, surname, role=role_visitor))
        db_session.commit()

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

        db = DataBase()
        db_session = db.create_session()
        user = db_session.query(db.User).filter_by(email=email).first()

        if not user or hashed_password != user.password:
            raise PermissionError('Incorrect login or password')

        user_session = db_session.query(db.Session).filter_by(user_id=user.id).first()

        if user_session and user_session.exp_dt >= datetime.now():
            return user_session.uuid

        elif user_session:
            db_session.delete(user_session)

        user_session = db.Session(user)
        db_session.add(user_session)
        user.last_login_dt = datetime.now()
        db_session.commit()
        
        return user_session.uuid

    @staticmethod
    def logout(session_id: str):
        """Logout user.

        Args:
            session_id (str): session UUID.

        """

        db = DataBase()
        db_session = db.create_session()
        db_session.query(db.Session).filter_by(uuid=session_id).delete()
        db_session.commit()
