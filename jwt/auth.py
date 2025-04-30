from fastapi import HTTPException
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer

from constants import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS

fake_users_db = {}
refresh_token_db = {}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    # TODO: create the docsctring
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    # TODO: create the docsctring
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str):
    # TODO: create the docsctring
    user = fake_users_db.get(username)
    
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    
    return {"username": username}


def create_access_token(data: dict, expires_delta: timedelta):
    # TODO: create the docsctring
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_tokens(username: str):
    # TODO: create the docsctring
    access_token = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    )
    refresh_token = create_access_token(
        data={"sub": username, "type": "refresh"}, 
        expires_delta=timedelta(days=int(REFRESH_TOKEN_EXPIRE_DAYS))
    )
    
    refresh_token_db[username] = refresh_token
    return access_token, refresh_token
    
    
def verify_token(token: str, expected_type: str = "access"):
    # TODO: create the docsctring
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != expected_type and expected_type == "refresh":
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")