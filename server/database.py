# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.orm.session import Session as DBSession
from sqlalchemy.engine.base import Engine
from datetime import datetime, timedelta
from uuid import uuid4
from server.crypto import HashAPI
from server.utils import SingletonMeta


class DataBase(metaclass=SingletonMeta):
    """Singleton class for ORM.

    """

    __is_inited = False
    __instance = None
    __db_string = "postgres://{}:{}@{}/{}".format(
        os.environ['DB_USER'],
        os.environ['DB_PASSWORD'],
        os.environ['DB_HOST'],
        os.environ['DB_NAME'])
    Base = declarative_base()

    def __init__(self):
        pass

    class BaseModel:
        """Base database model.

        """

        @declared_attr
        def __tablename__(self):
            pass

        id = Column(Integer, name='Id', primary_key=True, autoincrement=True)
        create_dt = Column(DateTime, name='Create Date')

        def __init__(self):
            pass

    class User(BaseModel, Base):
        """User model.

        """

        email = Column(String, name='Email', unique=True)
        password = Column(String, name='Password')
        name = Column(String, name='Name')
        surname = Column(String, name="Surname")
        last_login_dt = Column(DateTime, name="Last Login Date")
        role_id = Column(Integer, ForeignKey('Role.Id', ondelete='CASCADE', onupdate='CASCADE'))
        role = relationship('Role', back_populates='users')
        sessions = relationship('Session', back_populates='user', cascade='all, delete-orphan')

        def __init__(self, email: str, password: str, name: str, surname: str = None, role=None, sessions: list = None):
            pass

    class Role(BaseModel, Base):
        """Role model.

        """

        name = Column(String, name='Name', unique=True)
        users = relationship('User', back_populates='role', cascade='all, delete-orphan')
        methods = relationship('MethodRole', back_populates='role')

        def __init__(self, name: str, users: list = None, methods: list = None):
            pass

    class Method(BaseModel, Base):
        """Method model.

        """

        name = Column(String, name='Name', unique=True)
        shared = Column(Boolean, name='Shared', default=False)
        roles = relationship('MethodRole', back_populates='method')

        def __init__(self, name: str, shared: bool = False, roles: list = None):
            pass

    class Session(BaseModel, Base):
        """Session model.

        """

        uuid = Column(String, name='UUID', unique=True)
        exp_dt = Column(DateTime, name='Expiration Date')
        user_id = Column(Integer, ForeignKey('User.Id', ondelete='CASCADE', onupdate='CASCADE'))
        user = relationship('User', back_populates='sessions')

        def __init__(self, user=None):
            pass

    class MethodRole(Base):
        """Many to many model for method and role models.

        """

        __tablename__ = 'MethodRole'

        def __init__(self, method=None, role=None):
            pass

        method_id = Column(Integer, ForeignKey('Method.Id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
        method = relationship('Method', back_populates='roles')
        role_id = Column(Integer, ForeignKey('Role.Id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
        role = relationship('Role', back_populates='methods')

    @property
    def engine(self) -> Engine:
        """Database engine getter.

        Returns:
            Database engine.

        """

        pass

    def create_session(self) -> DBSession:
        """Create and get database connection session.

        Returns:
            Database connection session.

        """

        pass

    def init_system(self):
        """Initialize database.

        """

        pass
