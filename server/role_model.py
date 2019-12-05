from aiohttp import web
from .database import DataBase


class RoleModel:

    @staticmethod
    def role_model(func):

        def wrapper(*args, **kwargs) -> web.Response:
            request = args[1]
            session_id = request.headers.get('Authorization')

            if not session_id:
                raise web.HTTPForbidden()

            try:
                db = DataBase()
                db_session = db.create_session()
                session = db_session.query(db.Session).filter_by(uuid=session_id).first()
                assert session, 'Session expired. Please, sign in again'
                method = db_session.query(db.Method).filter_by(name=func.__name__).first()

                if method and not method.shared:
                    relations = set(filter(lambda rel: rel.role_id == session.user.role.id, method.roles))
                    assert len(relations) > 0, 'Access denied'

                return func(*args, **kwargs)

            except AssertionError as err:
                return web.json_response(data={
                    'status': 'error',
                    'message': '{}'.format(err),
                })

        return wrapper

    @staticmethod
    def add_method(method_name: str):
        db = DataBase()
        db_session = db.create_session()
        existing_method = db_session.query(db.Method).filter_by(name=method_name).first()
        assert not existing_method, 'Method {} is already exists'.format(method_name)
        db_session.add(db.Method(method_name))
        db_session.commit()

    @staticmethod
    def delete_method(method_name: str):
        db = DataBase()
        db_session = db.create_session()
        method = db_session.query(db.Method).filter_by(name=method_name).first()
        assert method, 'Method {} is not found'.format(method_name)
        db_session.delete(method)
        db_session.commit()

    @staticmethod
    def add_role(role_name: str):
        db = DataBase()
        db_session = db.create_session()
        existing_role = db_session.query(db.Role).filter_by(name=role_name).first()
        assert not existing_role, 'Role {} is already exists'.format(role_name)
        db_session.add(db.Role(role_name))
        db_session.commit()

    @staticmethod
    def delete_role(role_name: str):
        db = DataBase()
        db_session = db.create_session()
        role = db_session.query(db.Role).filter_by(name=role_name).first()
        assert role, 'Role {} is not found'.format(role_name)
        assert not len(role.users), "You can't delete role with users"
        db_session.delete(role)
        db_session.commit()

    @staticmethod
    def add_method_to_role(**kwargs):
        method_name = kwargs.get('method')
        role_name = kwargs.get('role')

        assert method_name and (method_name := method_name.strip()), 'Method name is not set'
        assert role_name and (role_name := role_name.strip()), 'Role name is not set'

        db = DataBase()
        db_session = db.create_session()
        method = db_session.query(db.Method).filter_by(name=method_name).first()
        role = db_session.query(db.Role).filter_by(name=role_name).first()
        assert method, 'Method {} is not found'.format(method_name)
        assert role, 'Role {} is not found'.format(role_name)
        relations = set(filter(lambda rel: rel.role_id == role.id, method.roles))
        assert not len(relations), 'Method {} already exists in role {}'.format(method_name, role_name)
        role.methods.append(db.MethodRole(method=method))
        db_session.commit()

    @staticmethod
    def delete_method_from_role(**kwargs):
        method_name = kwargs.get('method')
        role_name = kwargs.get('role')

        assert method_name and (method_name := method_name.strip()), 'Method name is not set'
        assert role_name and (role_name := role_name.strip()), 'Role name is not set'

        db = DataBase()
        db_session = db.create_session()
        method = db_session.query(db.Method).filter_by(name=method_name).first()
        role = db_session.query(db.Role).filter_by(name=role_name).first()
        assert method, 'Method {} is not found'.format(method_name)
        assert role, 'Role {} is not found'.format(role_name)
        relations = set(filter(lambda rel: rel.role_id == role.id, method.roles))
        assert len(relations), 'Method {} is not found in role {}'.format(method_name, role_name)
        db_session.delete(list(relations)[0])
        db_session.commit()

    @staticmethod
    def change_shared_prop(**kwargs):
        method_name = kwargs.get('method')
        value = kwargs.get('value')

        assert method_name and (method_name := method_name.strip()), 'Method name is not set'
        assert value is not None, 'Value is not set'
        assert isinstance(value, bool), 'Value should be boolean'

        db = DataBase()
        db_session = db.create_session()
        method = db_session.query(db.Method).filter_by(name=method_name).first()
        assert method, 'Method {} is not found'.format(method_name)
        method.shared = value
        db_session.commit()

    @staticmethod
    def change_user_role(**kwargs):
        email = kwargs.get('email')
        role_name = kwargs.get('role')

        assert email and (email := email.strip()), 'Email is not set'
        assert role_name and (role_name := role_name.strip()), 'Role name is not set'

        db = DataBase()
        db_session = db.create_session()
        user = db_session.query(db.User).filter_by(email=email).first()
        role = db_session.query(db.Role).filter_by(name=role_name).first()
        assert user, 'User with email {} is not found'.format(email)
        assert role, 'Role {} is not found'.format(role_name)
        user.role = role
        db_session.commit()