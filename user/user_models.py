from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine('sqlite:///users.db')
Base = declarative_base()


# Setup sqlalchemy tables
class User(Base):

    __tablename__ = 'user'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50))
    password = Column(String(50))
    email = Column(String(50))
    role = Column(String(10))

    def __init__(self, username, password, email, role="user"):
        # self.user_id = user_id
        self.username = username
        self.password = password
        self.email = email
        self.role = role

    def __repr__(self):
        return f"User(id='{self.username}')"

    def __str__(self):
        return self.__repr__()

    def match_password(self, password):
        if password != self.password:
            return False
        return True

    def to_dict(self):
        return {'user_id': self.user_id, 'username': self.username, 'email': self.email, 'role': self.role}


class Session(Base):

    __tablename__ = 'sessions'
    session_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer)
    refresh_token = Column(String(50))
    expires_in = Column(String(50))
    ip = Column(String(20))

    def __init__(self, user_id, refresh_token, expires_in, ip):
        self.user_id = user_id
        self.refresh_token = refresh_token
        self.expires_in = expires_in
        self.ip = ip

    def to_dict(self):
        return {'session_id': self.session_id, 'user': self.user_id}


if __name__ == "__main__":
    Base.metadata.create_all(engine)
