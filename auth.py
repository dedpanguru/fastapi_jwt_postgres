import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import bcrypt
from datetime import datetime, timedelta


class AuthHandler:
    security = HTTPBearer()
    secret = 'SECRET'

    def get_password_hash(self, password: str):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def validate_password(self, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

    def generate_token(self, username):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, hours=1),
            'iat': datetime.utcnow(),
            'sub': username
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def validate_token(self, token: str):
        try:
            jwt.decode(token.encode(), self.secret, algorithms=['HS256'], options={'verify_exp': True})
            return token
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Expired Token')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid token')

    def validate_auth_header(self, auth: HTTPAuthorizationCredentials = Security(security)):
        return self.validate_token(auth.credentials)
