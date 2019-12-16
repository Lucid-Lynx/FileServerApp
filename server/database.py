import os
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime, timedelta
from uuid import uuid4
from server.crypto import HashAPI
from server.utils import SingletonMeta


class DataBase(metaclass=SingletonMeta):

    __is_inited = False
    __instance = None
    __db_string = "postgres://{}:{}@{}/{}".format(
        os.environ['DB_USER'],
        os.environ['DB_PASSWORD'],
        os.environ['DB_HOST'],
        os.environ['DB_NAME'])
    Base = declarative_base()

    def __init__(self):
        if not self.__is_inited:
            self.__engine = create_engine(self.__db_string, pool_size=10, max_overflow=20)
            self.Base.metadata.create_all(bind=self.__engine)
            self.__is_inited = True

    class BaseModel:

        @declared_attr
        def __tablename__(self):
            return self.__name__

        id = Column(Integer, name='Id', primary_key=True, autoincrement=True)
        create_dt = Column(DateTime, name='Create Date')

        def __init__(self):
            self.create_dt = datetime.now()

    class User(BaseModel, Base):

        email = Column(String, name='Email', unique=True)
        password = Column(String, name='Password')
        name = Column(String, name='Name')
        surname = Column(String, name="Surname")
        last_login_dt = Column(DateTime, name="Last Login Date")
        role_id = Column(Integer, ForeignKey('Role.Id', ondelete='CASCADE', onupdate='CASCADE'))
        role = relationship('Role', back_populates='users')
        sessions = relationship('Session', back_populates='user', cascade='all, delete-orphan')

        def __init__(self, email: str, password: str, name: str, surname: str = None, role=None, sessions: list = None):
            super().__init__()
            self.email = email
            self.password = password
            self.name = name
            self.surname = surname
            self.role = role

            if sessions:
                self.sessions.extend(sessions)

    class Role(BaseModel, Base):

        name = Column(String, name='Name', unique=True)
        users = relationship('User', back_populates='role', cascade='all, delete-orphan')
        methods = relationship('MethodRole', back_populates='role')

        def __init__(self, name: str, users: list = None, methods: list = None):
            super().__init__()
            self.name = name

            if users:
                self.users.extend(users)

            if methods:
                method_role_list = map(lambda method: DataBase.MethodRole(method=method), methods)
                self.methods.extend(method_role_list)

    class Method(BaseModel, Base):

        name = Column(String, name='Name', unique=True)
        shared = Column(Boolean, name='Shared', default=False)
        roles = relationship('MethodRole', back_populates='method')

        def __init__(self, name: str, shared: bool = False, roles: list = None):
            super().__init__()
            self.name = name
            self.shared = shared

            if roles:
                method_role_list = list(map(lambda role: DataBase.MethodRole(role=role), roles))
                self.roles.extend(method_role_list)

    class Session(BaseModel, Base):

        uuid = Column(String, name='UUID', unique=True)
        exp_dt = Column(DateTime, name='Expiration Date')
        user_id = Column(Integer, ForeignKey('User.Id', ondelete='CASCADE', onupdate='CASCADE'))
        user = relationship('User', back_populates='sessions')

        def __init__(self, user=None):
            super().__init__()
            self.uuid = str(uuid4())
            self.exp_dt = self.create_dt + timedelta(hours=int(os.environ['SESSION_DURATION_HOURS']))
            self.user = user

    class MethodRole(Base):

        __tablename__ = 'MethodRole'

        def __init__(self, method=None, role=None):
            self.method = method
            self.role = role

        method_id = Column(Integer, ForeignKey('Method.Id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
        method = relationship('Method', back_populates='roles')
        role_id = Column(Integer, ForeignKey('Role.Id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
        role = relationship('Role', back_populates='methods')

    @property
    def engine(self):
        return self.__engine

    def create_session(self):
        return sessionmaker(bind=self.__engine)()

    def init_system(self):
        self.Base.metadata.drop_all(bind=self.__engine)
        self.Base.metadata.create_all(bind=self.__engine)
        session = self.create_session()
        role_visitor = self.Role('visitor')
        role_trusted = self.Role('trusted')
        role_admin = self.Role(
            'admin',
            users=[self.User('admin@fileserver.su', HashAPI.hash_sha512(os.environ['ADMIN_PASSWORD']), 'Admin')])
        session.add_all([
            self.Method('get_files', roles=[role_visitor, role_trusted, role_admin]),
            self.Method('get_file_info', roles=[role_visitor, role_trusted, role_admin]),
            self.Method('get_file_info_signed', roles=[role_visitor, role_trusted, role_admin]),
            self.Method('create_file', roles=[role_trusted, role_admin]),
            self.Method('delete_file', roles=[role_trusted, role_admin]),
            self.Method('add_method', roles=[role_admin]),
            self.Method('delete_method', roles=[role_admin]),
            self.Method('add_role', roles=[role_admin]),
            self.Method('delete_role', roles=[role_admin]),
            self.Method('add_method_to_role', roles=[role_admin]),
            self.Method('delete_method_from_role', roles=[role_admin]),
            self.Method('change_shared_prop', roles=[role_admin]),
            self.Method('change_user_role', roles=[role_admin]),
            self.Method('change_file_dir', roles=[role_admin]),
        ])
        session.commit()
