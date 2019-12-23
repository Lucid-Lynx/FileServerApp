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

            pass

        pass
