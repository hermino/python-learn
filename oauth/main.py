from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from starlette.responses import JSONResponse
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware

from google_auth_oauthlib.flow import Flow

import os
import pathlib
import requests


config = Config(".env")
app = FastAPI()

app.add_middleware(             
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=config("SECRET_KEY"),
)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

CLIENT_SECRET_FILE = config("GOOGLE_CLIENT_SECRET_FILE")
SCOPES = ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"]
REDIRECT_URI = config("REDIRECT_URI")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get("user")
    if user:
        return f"<h1>Olá, {user['name']}</h1><p>{user['email']}</p><a href='/logout'>Logout</a>"
    else:
        return "<a href='/login'>Login</a>"

@app.get("/login")
async def login(request: Request):
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true")
    
    request.session["state"] = state
    return RedirectResponse(url=authorization_url)
    

@app.get("/callback")
async def callback(request: Request):
    """
    state = request.session.get("state")
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI,
    )
    
    flow.fetch_token(authorization_response=str(request.url))
    
    credentials = flow.credentials
    response = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        params={"alt": "json"},
        headers={"Authorization": f"Bearer {credentials.token}"},
    )
    
    user_info = response.json()
    
    request.session["user"] = {
        "name": user_info["name"],
        "email": user_info["email"],
        "picture": user_info["picture"],
    }
    
    return RedirectResponse(url="/")
    """
    
    state = request.session.get("state")
    print(request.url)
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI,
    )
    
    flow.fetch_token(authorization_response=str(request.url))
    credentials = flow.credentials
    return {
        "access_token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "scopes": credentials.scopes
    }
    
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")
    
    

