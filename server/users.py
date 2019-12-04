import re
from .database import DataBase
from .crypto import CryptoAPI


EMAIL_REGEX = re.compile(r'[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}$')
PASSWORD_REGEX = re.compile(r'^\w{8,50}$')


class UsersAPI:

    @staticmethod
    def signup(**kwargs):

        email = kwargs.get('email')
        password = kwargs.get('password')
        confirm_password = kwargs.get('confirm_password')
        name = kwargs.get('name')
        surname = kwargs.get('surname')

        assert email and (email := email.strip()), 'Email is not set'
        assert password and (password := password.strip()), 'Password is not set'
        assert confirm_password and (confirm_password := confirm_password.strip()), 'Please, repeat the password'
        assert name and (name := name.strip()), 'Name is not set'
        assert EMAIL_REGEX.match(email), 'Invalid email format'
        assert PASSWORD_REGEX.match(password), \
            'Invalid password. Password should contain letters, digits and will be 8 to 50 characters long'
        assert password == confirm_password, 'Passwords are not match'

        if surname:
            surname = surname.strip()

        hashed_password = CryptoAPI.hash_sha512(password)

        db = DataBase()
        db_session = db.create_session()
        existed_user = db_session.query(db.User).filter_by(email=email).first()
        assert not existed_user, 'User with email {} is already exists'.format(email)
        role_visitor = db_session.query(db.Role).filter_by(name="Visitor").first()
        db_session.add(db.User(email, hashed_password, name, surname, role=role_visitor))
        db_session.commit()

    @staticmethod
    def signin(**kwargs) -> str:

        email = kwargs.get('email')
        password = kwargs.get('password')

        assert email and (email := email.strip()), 'Email is not set'
        assert password and (password := password.strip()), 'Password is not set'
        assert EMAIL_REGEX.match(email), 'Invalid email format'

        hashed_password = CryptoAPI.hash_sha512(password)

        db = DataBase()
        db_session = db.create_session()
        user = db_session.query(db.User).filter_by(email=email).first()
        assert user and hashed_password == user.password, 'Invalid login or password'.format(email)
        user_session = db.Session(user)
        db_session.add(user_session)
        db_session.commit()
        
        return user_session.uuid

    @staticmethod
    def logout(session_id: str):

        db = DataBase()
        db_session = db.create_session()
        db_session.query(db.Session).filter_by(uuid=session_id).delete()
        db_session.commit()

