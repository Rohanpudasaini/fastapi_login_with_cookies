from fastapi import FastAPI, Depends, Request, Response, Cookie
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_login.exceptions import InvalidCredentialsException
from pydantic import BaseModel

class User(BaseModel):
    username:str
    email:str|None = None
    full_name:str|None = None
    disabled:bool|None = None
    

app = FastAPI(title="Testing PasswordBase Login")

oAuthScheme = OAuth2PasswordBearer(tokenUrl='login')

import base64

def user_to_cookie(username: str,staff:bool=False) -> str:
    return base64.b64encode(f"username={username},staff={staff}".encode()).decode()

def cookie_to_user(cookie: str) -> str:
    cookie_result = base64.b64decode(cookie)
    return cookie_result

fake_db ={
    'admin':{'password':'admin','staff':True},
    'rohan':{'password':'rohan1','staff':False},
    'ganesh':{'password':'ganesh1213', 'staff':False}
}

@app.post('/login')
async def login(response:Response,data:OAuth2PasswordRequestForm = Depends()):
    username = data.username
    password = data.password
    # if username =='admin' and password == 'admin':
    if username in fake_db.keys():
        if password == fake_db[username]['password']:
            staff=False
            if username == "admin":staff=True
            value = user_to_cookie(username, staff)
            response.set_cookie(key='cookie',value=value)
            return "Login Sucessfull"
    raise InvalidCredentialsException

@app.get('/items')
async def get_items(
    # token: Annotated[str, Depends(oAuthScheme)],
    cookie: str = Cookie(None),
    ):
    print(cookie)
    return {
        'cookie_decoded':cookie_to_user(cookie.encode())
    }

@app.get("/get-cookie")
def get_cookie(cookie: str = Cookie(None)):
    return {"mycookie": cookie}

# @app.get('/current_user')
# def get_current_user(cookie: str = Cookie(None)):
    # 
   