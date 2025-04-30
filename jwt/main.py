import uvicorn
from fastapi import HTTPException, FastAPI, Depends
from fastapi.security import OAuth2PasswordRequestForm
from auth import (fake_users_db, refresh_token_db, get_password_hash, 
                  authenticate_user, create_tokens, verify_token, oauth2_scheme)
from models import Token, User

app = FastAPI()


@app.post("/register")
async def register(user: User):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")

    fake_users_db[user.username] = {
        "username": user.username,
        "hashed_password": get_password_hash(user.password)
    }
    
    return {"message": "User registered successfully"}


@app.post("/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token, refresh_token = create_tokens(user["username"])
    
    print(access_token, refresh_token)
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@app.post("/refresh", response_model=Token)
async def refresh(refresh_token: str):
    username = verify_token(refresh_token, expected_type="refresh")
    if refresh_token_db.get(username) != refresh_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    access_token, refresh_token_ = create_tokens(username)

    refresh_token_db[username] = refresh_token_
    return Token(
        access_token=access_token,
        refresh_token=refresh_token_,
        token_type="bearer"
    )


@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    return {"msg": f"Bem-vindo, {username}!"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)