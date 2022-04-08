import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = f'postgresql://{os.environ["DBUSER"]}:{os.environ["DBPASS"]}@{os.environ["DBHOST"]}/{os.environ["DBNAME"]}'

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def new_db_conn() -> SessionLocal:
    db = SessionLocal()
    try:
        yield db
    except:
        db.close()
