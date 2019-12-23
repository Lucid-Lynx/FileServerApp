# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import re
from datetime import datetime
from aiohttp import web
from server.database import DataBase
from server.crypto import HashAPI


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
                *args (tuple): Tuple with nameless arguments,
                **kwargs (dict): Dict with named arguments.

            Returns:
                Result of called wrapped method.

            Raises:
                HTTPUnauthorized: 401 HTTP error, if user session is expired or not found.

            """

            pass

        pass

    @staticmethod
    def signup(**kwargs):
        """Sign up new user.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                email (str): user's email. Required.
                password (str): user's password. Required letters and numbers. Quantity of symbols > 8 and < 50.
                Required.
                confirm_password (str): password confirmation. Must match with password. Required.
                name (str): user's first name. Required.
                surname (str): user's last name. Optional. Required.

        Raises:
            AssertionError: if at least one of required parameters in kwargs is not set, user with set email exists,
            email or password format is invalid, passwords are not match.

        """

        pass

    @staticmethod
    def signin(**kwargs) -> str:
        """Sign in user.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                email (str): user's email. Required.
                password (str): user's password. Required.

        Returns:
            Str with session UUID.

        Raises:
            AssertionError: if at least one of required parameters in kwargs is not set, user does not exist,
            email format is invalid, incorrect password.

        """

        pass

    @staticmethod
    def logout(session_id: str):
        """Logout user.

        Args:
            session_id (str): session UUID.

        """

        pass
