from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine('sqlite:///offers.db')
Base = declarative_base()


# Setup sqlalchemy tables
class Offer(Base):

    __tablename__ = 'offers'
    offer_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer)
    title = Column(String(100))
    text = Column(String(2000))

    def __init__(self, user_id, title, text):
        # self.offer_id = offer_id
        self.user_id = user_id
        self.title = title
        self.text = text

    def __repr__(self):
        return f"Offer(id='{self.offer_id}', user='{self.user_id}')"

    def __str__(self):
        return self.__repr__()

    def to_dict(self):
        return {"offer_id": self.offer_id, "user_id": self.user_id, "title": self.title, "text": self.text}


if __name__ == "__main__":
    Base.metadata.create_all(engine)
