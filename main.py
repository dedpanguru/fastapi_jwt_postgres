import os.path

from fastapi import FastAPI, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse

from models import User
from auth import AuthHandler
from database import new_db_conn
from schema import Credentials

app = FastAPI()
security = AuthHandler()


@app.middleware('http')
async def middleware(request: Request, call_next):
    # check content-type header
    if request.headers['Content-Type']:
        if request.headers['Content-Type'] == 'application/json':
            return await call_next(request)
    else:
        raise HTTPException(status_code=400, detail='Invalid Header')


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}


@app.post("/api/register", status_code=201)
async def register(credentials: Credentials, db: Session = Depends(new_db_conn)):
        # check if user already in db
        if get_user(credentials.username, db):
            raise HTTPException(status_code=401, detail='User has an account already')
        # generate new token
        token = security.generate_token(credentials.username)
        # request db
        create_user(User(
            username=credentials.username,
            password=security.get_password_hash(credentials.password),
            token=token
        ), db)
        # send token back
        return {'token': token}


@app.post('/api/login', status_code=202)
async def login(credentials: Credentials, db: Session = Depends(new_db_conn)):
    # validate username
    user = get_user(credentials.username, db)
    if not user:
        raise HTTPException(status_code=401, detail='invalid username')
    # validate input password
    if not security.validate_password(credentials.password, user.password):
        raise HTTPException(status_code=401, detail='invalid password')
    # determine if token needs to be refreshed
    refresh_needed = not user.token  # refresh if token was deleted
    if not refresh_needed:
        # validate token in db
        try:
            security.validate_token(user.token)
        except HTTPException as e:
            if e.detail == 'Expired Token':
                refresh_needed = True  # refresh if token is expired
            else:
                raise e
    # refresh token if needed
    if refresh_needed:
        user.token = security.generate_token(user.username)
        update_user_token(user, db)
        return {'token': user.token}


@app.post('/api/logout', status_code=202)
async def logout(credentials: Credentials, db: Session = Depends(new_db_conn), token=Depends(security.validate_auth_header)):
    # validate username
    user = get_user(credentials.username, db)
    if not user:
        raise HTTPException(status_code=401, detail='invalid username')
    # validate input password
    if not security.validate_password(credentials.password, user.password):
        raise HTTPException(status_code=401, detail='invalid password')
    # validate token in db
    if not user.token:
        return
    try:
        security.validate_token(user.token)
    except HTTPException as e:
        if e.detail == 'Expired Token':
            return
        else:
            raise e
    # validate input token
    try:
        security.validate_token(token)
    except HTTPException as e:
        raise e
    if token != user.token:
        raise HTTPException(status_code=401, detail='Invalid token')
    user.token = None
    update_user_token(user, db)


@app.get('/api/assets/{file}', response_class=FileResponse)
async def resource(file: str, credentials: Credentials, db: Session = Depends(new_db_conn), token: str = Depends(security.validate_auth_header)):
    # validate username
    user = get_user(credentials.username, db)
    if not user:
        raise HTTPException(status_code=401, detail='invalid username')
    # validate input password
    if not security.validate_password(credentials.password, user.password):
        raise HTTPException(status_code=401, detail='invalid password')
    # validate token in db
    if not user.token:
        return
    try:
        security.validate_token(user.token)
    except HTTPException as e:
        if e.detail == 'Expired Token':
            return
        else:
            raise e
    # validate input token
    try:
        security.validate_token(token)
    except HTTPException as e:
        raise e
    if token != user.token:
        raise HTTPException(status_code=401, detail='Invalid token')
    # check if resource is in assets folder
    if os.path.exists('./assets/'+file):
        return './assets/'+file
    else:
        raise HTTPException(status_code=404, detail='File Not Found')


# Define DB operations here
def create_user(user: User, db: Session):
    db.add(user)
    db.commit()
    db.close()


def get_user(username: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    db.close()
    return user


def update_user_token(user: User, db: Session):
    db.query(User).filter(User.username == user.username).update({User.token: user.token})
    db.close()
