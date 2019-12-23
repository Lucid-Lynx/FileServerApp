# Copyright 2019 by Kirill Kanin.
# All rights reserved.

from aiohttp import web
from server.database import DataBase


class RoleModel:
    """Class with static methods for working with role model via ORM.

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

    @staticmethod
    def add_method(method_name: str):
        """Add new method.

        Args:
            method_name (str): Method name.

        Raises:
            AssertionError: if method exists.

        """

        pass

    @staticmethod
    def delete_method(method_name: str):
        """Delete method.

        Args:
            method_name (str): Method name.

        Raises:
            AssertionError: if method does not exist.

        """

        pass

    @staticmethod
    def add_role(role_name: str):
        """Add new role.

        Args:
            role_name (str): Role name.

        Raises:
            AssertionError: if role exists.

        """

        pass

    @staticmethod
    def delete_role(role_name: str):
        """Delete role.

        Args:
            role_name (str): Role name.

        Raises:
            AssertionError: if role does not exist.

        """

        pass

    @staticmethod
    def add_method_to_role(**kwargs):
        """Add method to role.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                method_name (str): Method name. Required.
                role_name (str): Role name. Required.

        Raises:
            AssertionError: if at least one required parameter in kwargs is not set, method is not found, role is not
            found, method is already added to role.

        """

        pass

    @staticmethod
    def delete_method_from_role(**kwargs):
        """Delete method from role.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                method_name (str): Method name. Required.
                role_name (str): Role name. Required.

        Raises:
            AssertionError: if at least one required parameter in kwargs is not set, method is not found, role is not
            found, method is not found in role.

        """

        pass

    @staticmethod
    def change_shared_prop(**kwargs):
        """Change method's shared property.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                method_name (str): Method name. Required.
                value (bool): Value of shared property. Required.

        Raises:
            AssertionError: if at least one required parameter in kwargs is not set, method is not found, value is not
            boolean.

        """

        pass

    @staticmethod
    def change_user_role(**kwargs):
        """Change user role.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                email (str): User's email. Required.
                role_name (str): Role name. Required.

        Raises:
            AssertionError: if at least one required parameter in kwargs is not set, user is not found, role is not
            found.

        """

        pass
