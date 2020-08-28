# Copyright 2019 by Kirill Kanin.
# All rights reserved.

from aiohttp import web
from server.db.database import DataBase


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
                *args (tuple): Tuple with nameless arguments;
                **kwargs (dict): Dict with named arguments.

            Returns:
                Result of called wrapped method.

            Raises:
                HTTPUnauthorized: 401 HTTP error, if user session is expired or not found;
                HTTPForbidden: 403 HTTP error, if access denied.

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

            if not session.user.role:
                raise web.HTTPForbidden(text='User is not attached to role')

            method = db_session.query(db.Method).filter_by(name=func.__name__).first()

            if method and not method.shared:
                relations = set(filter(lambda rel: rel.role_id == session.user.role.id, method.roles))

                if len(relations) == 0:
                    raise web.HTTPForbidden(text='Access denied')

            return func(*args, **kwargs)

        return wrapper

    @staticmethod
    def add_method(method_name: str):
        """Add new method.

        Args:
            method_name (str): Method name.

        Raises:
            SystemError: if method exists.

        """

        db = DataBase()
        db_session = db.create_session()
        existing_method = db_session.query(db.Method).filter_by(name=method_name).first()

        if existing_method:
            raise SystemError(f'Method {method_name} already exists')

        db_session.add(db.Method(method_name))
        db_session.commit()

    @staticmethod
    def delete_method(method_name: str):
        """Delete method.

        Args:
            method_name (str): Method name.

        Raises:
            SystemError: if method does not exist.

        """

        db = DataBase()
        db_session = db.create_session()
        method = db_session.query(db.Method).filter_by(name=method_name).first()

        if not method:
            raise SystemError(f'Method {method_name} is not found')

        db_session.query(db.MethodRole).filter_by(method_id=method.id).delete()
        db_session.delete(method)
        db_session.commit()

    @staticmethod
    def add_role(role_name: str):
        """Add new role.

        Args:
            role_name (str): Role name.

        Raises:
            SystemError: if role exists.

        """

        db = DataBase()
        db_session = db.create_session()
        existing_role = db_session.query(db.Role).filter_by(name=role_name).first()

        if existing_role:
            raise SystemError(f'Role {role_name} already exists')

        db_session.add(db.Role(role_name))
        db_session.commit()

    @staticmethod
    def delete_role(role_name: str):
        """Delete role.

        Args:
            role_name (str): Role name.

        Raises:
            SystemError: if role does not exist, if role has users.

        """

        db = DataBase()
        db_session = db.create_session()
        role = db_session.query(db.Role).filter_by(name=role_name).first()

        if not role:
            raise SystemError(f'Role {role_name} is not found')

        if len(role.users):
            raise SystemError("You can't delete role with users")

        db_session.query(db.MethodRole).filter_by(role_id=role.id).delete()
        db_session.delete(role)
        db_session.commit()

    @staticmethod
    def add_method_to_role(**kwargs):
        """Add method to role.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                method_name (str): Method name. Required;
                role_name (str): Role name. Required.

        Raises:
            ValueError: if at least one required parameter in kwargs is not set;
            SystemError: method is not found, role is not found, method is already added to role.

        """

        method_name = kwargs.get('method')
        role_name = kwargs.get('role')

        if not method_name or not (method_name := method_name.strip()):
            raise ValueError('Method name is not set')

        if not role_name or not (role_name := role_name.strip()):
            raise ValueError('Role name is not set')

        db = DataBase()
        db_session = db.create_session()
        method = db_session.query(db.Method).filter_by(name=method_name).first()
        role = db_session.query(db.Role).filter_by(name=role_name).first()

        if not method:
            raise SystemError(f'Method {method_name} is not found')

        if not role:
            raise SystemError(f'Role {role_name} is not found')

        relations = set(filter(lambda rel: rel.role_id == role.id, method.roles))
        if len(relations):
            raise SystemError(f'Method {method_name} already exists in role {role_name}')

        role.methods.append(db.MethodRole(method=method))
        db_session.commit()

    @staticmethod
    def delete_method_from_role(**kwargs):
        """Delete method from role.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                method_name (str): Method name. Required;
                role_name (str): Role name. Required.

        Raises:
            ValueError: if at least one required parameter in kwargs is not set;
            SystemError: method is not found, role is not found, method is not found in role.

        """

        method_name = kwargs.get('method')
        role_name = kwargs.get('role')

        if not method_name or not (method_name := method_name.strip()):
            raise ValueError('Method name is not set')

        if not role_name or not (role_name := role_name.strip()):
            raise ValueError('Role name is not set')

        db = DataBase()
        db_session = db.create_session()
        method = db_session.query(db.Method).filter_by(name=method_name).first()
        role = db_session.query(db.Role).filter_by(name=role_name).first()

        if not method:
            raise SystemError(f'Method {method_name} is not found')

        if not role:
            raise SystemError(f'Role {role_name} is not found')

        relations = set(filter(lambda rel: rel.role_id == role.id, method.roles))
        if not len(relations):
            raise SystemError(f'Method {method_name} is not found in role {role_name}')

        db_session.delete(list(relations)[0])
        db_session.commit()

    @staticmethod
    def change_shared_prop(**kwargs):
        """Change method's shared property.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                method_name (str): Method name. Required;
                value (bool): Value of shared property. Required.

        Raises:
            ValueError: if at least one required parameter in kwargs is not set, value is not boolean;
            SystemError: method is not found.

        """

        method_name = kwargs.get('method')
        value = kwargs.get('value')

        if not method_name or not (method_name := method_name.strip()):
            raise ValueError('Method name is not set')

        if not value:
            raise ValueError('Value is not set')

        if not isinstance(value, bool):
            raise ValueError('Value should be boolean')

        db = DataBase()
        db_session = db.create_session()
        method = db_session.query(db.Method).filter_by(name=method_name).first()

        if not method:
            raise SystemError(f'Method {method_name} is not found')

        method.shared = value
        db_session.commit()

    @staticmethod
    def change_user_role(**kwargs):
        """Change user role.

        Args:
            **kwargs (dict): Dict with named arguments. Keys:
                email (str): User's email. Required;
                role_name (str): Role name. Required.

        Raises:
            ValueError: if at least one required parameter in kwargs is not set;
            SystemError: user is not found, role is not found.

        """

        email = kwargs.get('email')
        role_name = kwargs.get('role')

        if not email or not (email := email.strip()):
            raise ValueError('Email is not set')

        if not role_name or not (role_name := role_name.strip()):
            raise ValueError('Role name is not set')

        db = DataBase()
        db_session = db.create_session()
        user = db_session.query(db.User).filter_by(email=email).first()
        role = db_session.query(db.Role).filter_by(name=role_name).first()

        if not user:
            raise SystemError(f'User with email {email} is not found')

        if not role:
            raise SystemError(f'Role {role_name} is not found')

        user.role = role
        db_session.commit()
