import os.path

import uvicorn
from fastapi import FastAPI, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse

from .models import User
from .auth import AuthHandler
from .database import new_db_conn
from .schema import Credentials

app = FastAPI()
security = AuthHandler()

routes = ['login', 'register', 'logout']


@app.middleware('http')
async def middleware(request: Request, call_next):
    i = request.url.path.split('/').index('api')+1 if 'api' in request.url.path.split('/') else None
    if i:
        if len(request.url.path.split('/')) >= i:
            if request.url.path.split('/')[i] in routes:
                # check content-type header
                if request.headers['Content-Type']:
                    if request.headers['Content-Type'] == 'application/json':
                        # no tokens should be sent to login and register endpoints
                        if request.url.path.split('/')[i] in ('login', 'register'):
                            if 'Authorization' in request.headers:
                                raise HTTPException(status_code=400, detail='Invalid Header')
                        return await call_next(request)
                raise HTTPException(status_code=400, detail='Invalid Header')
    return await call_next(request)


@app.post("/api/register", status_code=201)
async def register(credentials: Credentials, db: Session = Depends(new_db_conn)):
    # check if user already in db
    if get_user(credentials.username, db):
        raise HTTPException(status_code=401, detail='Username Taken')
    # generate new token
    token = security.generate_token(credentials.username)
    # request db
    create_user(User(
        username=credentials.username,
        password=security.get_password_hash(credentials.password),
        token=token
    ), db)
    db.close()
    # send token back
    return {'token': token}


@app.post('/api/login', status_code=202)
async def login(credentials: Credentials, db: Session = Depends(new_db_conn)):
    db_record = get_user(credentials.username, db)
    try:
        refresh_needed = validate_credentials(credentials, db_record, logging_in=True)
    except HTTPException as e:
        raise e
    else:
        if refresh_needed:
            db_record.token = security.generate_token(db_record.username)
            update_user_token(db_record, db)
            db.close()
            return {'token': db_record.token}
    finally:
        db.close()


@app.post('/api/logout', status_code=202)
async def logout(credentials: Credentials, db: Session = Depends(new_db_conn),
                 token=Depends(security.validate_auth_header)):
    db_record = get_user(credentials.username, db)
    try:
        refresh_needed = validate_credentials(credentials, db_record, input_token=token)
    except HTTPException as e:
        raise e
    else:
        if not refresh_needed:
            db_record.token = None
            update_user_token(db_record, db)
    finally:
        db.close()


@app.get('/api/assets/{filename}', response_class=FileResponse)
async def resource(filename: str, token: str = Depends(security.validate_auth_header), db: Session = Depends(new_db_conn)):
    if token_is_in_db(token, db):
        db.close()
        # check if resource is in assets folder
        if os.path.exists('./assets/' + filename):
            return './assets/' + filename
        else:  # resource not found, return 404
            raise HTTPException(status_code=404, detail='File Not Found')
    raise HTTPException(status_code=401, detail='Invalid token')


# Define DB operations here
def create_user(user: User, db: Session) -> None:
    db.add(user)
    db.commit()


def get_user(username: str, db: Session) -> User:
    user = db.query(User).filter(User.username == username).first()
    return user


def token_is_in_db(token: str, db: Session) -> bool:
    if db.query(User).filter(User.token == token).first():
        return True
    return False


def update_user_token(user: User, db: Session) -> None:
    db.query(User).filter(User.username == user.username).update({User.token: user.token})
    db.commit()
    db.refresh(user)


def validate_credentials(credentials: Credentials,
                         db_record: User,
                         logging_in: bool = False,
                         input_token: str = None) -> bool:
    """
    Determines the validity of a request
    :param credentials: json body as an object
    :param db_record: entry in database corresponding to json input
    :param logging_in: boolean value indicating the level of security regarding token validity
    :param input_token: jwt of request as a string
    :return: Boolean representing whether token in database should be refreshed
    """
    # validate input username
    if not db_record:
        raise HTTPException(status_code=401, detail='Invalid Username')

    # validate input password
    if not security.validate_password(credentials.password, db_record.password):
        raise HTTPException(status_code=401, detail='Invalid Password')

    # check if user is logged out
    if not db_record.token:
        # login endpoint does not require a valid token in the db
        # however, register and logout endpoints do require it
        if not logging_in:
            raise HTTPException(status_code=401, detail='User Is Logged Out')
        return True

    # validate token in database
    try:
        security.validate_token(db_record.token)
    except HTTPException as e:
        # login endpoint needs to know if token expired
        if not logging_in or e.detail != 'Expired Token':
            raise e
        return True
    else:  # only runs if no exceptions were thrown
        if logging_in:  # db token is valid, so user was logged in already
            raise HTTPException(status_code=400, detail='User is already logged in')

    # finally, validate the input token
    # input tokens aren't allowed to be sent to login endpoint by default thanks to middleware function
    # so you can assume that logged_in will always be false here
    # you can also assume that input_token should exist by now
    try:
        security.validate_token(input_token)
        # also check that input token is the same as the token in the database
        if input_token != db_record.token:
            raise HTTPException(status_code=401, detail='Invalid Token')
    except HTTPException as e:
        raise e
    return False


if __name__ == '__main__':
    uvicorn.run('main:app', port=8080, reload=False)
