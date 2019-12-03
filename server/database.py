import os
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime, timedelta
from uuid import uuid4


class DataBase:

    __is_inited = False
    __db_string = "postgres://{}:{}@{}/{}".format(
        os.environ['DB_USER'],
        os.environ['DB_PASSWORD'],
        os.environ['DB_HOST'],
        os.environ['DB_NAME'])
    Base = declarative_base()

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, '__instance'):
            cls.__instance = super(DataBase, cls).__new__(cls)
        return cls.__instance

    def __init__(self):
        if not self.__is_inited:
            self.__engine = create_engine(self.__db_string)
            self.Base.metadata.create_all(self.__engine)
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

        username = Column(String, name='Username')
        password = Column(String, name='Password')
        sessions = relationship('Session', back_populates='user')
        roles = relationship('UserRole', back_populates='role')

        def __init__(self, username: str, password: str):
            super().__init__()
            self.username = username
            self.password = password

    class Role(BaseModel, Base):

        name = Column(String, name='Name')
        users = relationship('UserRole', back_populates='user')
        methods = relationship('MethodRole', back_populates='method')

        def __init__(self, name: str):
            super().__init__()
            self.name = name

    class Method(BaseModel, Base):

        name = Column(String, name='Name')
        shared = Column(Boolean, name='Shared', default=False)
        roles = relationship('MethodRole', back_populates='role')

        def __init__(self, name: str, shared: bool):
            super().__init__()
            self.name = name
            self.shared = shared

    class Session(BaseModel, Base):

        uuid = Column(String, name='UUID', unique=True)
        exp_dt = Column(DateTime, name='Expiration Date')
        user_id = Column(Integer, ForeignKey('User.Id', ondelete='CASCADE', onupdate='CASCADE'))
        user = relationship('User', back_populates='sessions')

        def __init__(self, user_id: int):
            super().__init__()
            self.uuid = str(uuid4())
            self.exp_dt = self.create_dt + timedelta(hours=int(os.environ['PASSWORD_DURATION_HOURS']))
            self.user_id = user_id

    class UserRole(Base):
        __tablename__ = 'UserRole'

        user_id = Column(Integer, ForeignKey('User.Id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
        user = relationship('User', back_populates='roles')
        role_id = Column(Integer, ForeignKey('Role.Id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
        role = relationship('Role', back_populates='users')

        def __init__(self, user_id: int, role_id: int):
            self.user_id = user_id
            self.role_id = role_id

    class MethodRole(Base):
        __tablename__ = 'MethodRole'

        def __init__(self, method_id: int, role_id: int):
            self.method_id = method_id
            self.role_id = role_id

        method_id = Column(Integer, ForeignKey('Method.Id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
        method = relationship('Method', back_populates='roles')
        role_id = Column(Integer, ForeignKey('Role.Id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
        role = relationship('Role', back_populates='methods')

    @property
    def engine(self):
        return self.__engine

    def create_session(self):
        return sessionmaker(bind=self.__engine)()

