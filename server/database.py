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

    Base = declarative_base()

    def __init__(self):
        pass

    class BaseModel:
        """Base database model.

        """

        @declared_attr
        def __tablename__(self):
            pass

        def __init__(self):
            pass

    class User(BaseModel, Base):
        """User model.

        """

        def __init__(self, email: str, password: str, name: str, surname: str = None, role=None, sessions: list = None):
            pass

    class Role(BaseModel, Base):
        """Role model.

        """

        def __init__(self, name: str, users: list = None, methods: list = None):
            pass

    class Method(BaseModel, Base):
        """Method model.

        """

        def __init__(self, name: str, shared: bool = False, roles: list = None):
            pass

    class Session(BaseModel, Base):
        """Session model.

        """

        def __init__(self, user=None):
            pass

    class MethodRole(Base):
        """Many to many model for method and role models.

        """

        __tablename__ = 'MethodRole'

        def __init__(self, method=None, role=None):
            pass

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
