from sqlalchemy import String
from sqlalchemy.sql.schema import Column
from src.database import Base


class User(Base):
    __tablename__ = 'users'

    username = Column(String(255), primary_key=True)
    password = Column(String(255), nullable=False)
    token = Column(String(255), nullable=True)
