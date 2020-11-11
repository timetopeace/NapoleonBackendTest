import os
import binascii
import json as j
from datetime import datetime, timedelta

import jwt
import httpx
from sanic import Sanic
from sanic.response import json
from sanic.exceptions import ServerError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from user_models import User, Session

# JWT configurations
JWT_SECRET = 'zL38epCPf3AhdpQxGI9Vk9q4361cjud8CMq2a491MLAR7npuPj'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 600
JWT_EXP_REFRESH_DELTA_SECONDS = 86400

app = Sanic("user_service")

# Database connection
engine = create_engine('sqlite:///users.db')
DBSession = sessionmaker(bind=engine)


async def authorized(token, local=False):
    """
    Local function to verify JWT token.
    Get token and locale flag.
    If local=True return dict of payload parameters, if token not valid raise server error.
    If local=False return JSON response with curr_user_id and curr_user_role,
    if token not valid return response with error.
    """
    try:
        token = token.split()[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        curr_user_id = payload.get('user_id')
        curr_user_role = payload.get('role')
        response = {'curr_user_id': curr_user_id, 'curr_user_role': curr_user_role}
        if not local:
            response = json(response)
        return response
    except jwt.exceptions.ExpiredSignatureError:
        if local:
            raise ServerError("Token has expired", status_code=401)
        else:
            return json({'error': "Token has expired"}, status=401)
    except jwt.DecodeError:
        if local:
            ServerError("Token is invalid", status_code=401)
        else:
            return json({'error': "Token is invalid"}, status=401)
    except IndexError:
        if local:
            raise ServerError("Token is invalid", status_code=401)
        else:
            return json({'error': "Token is invalid"}, status=401)


@app.post('/auth')
async def auth(token):
    """
    API entry point to verify JWT token.
    Get JSON request with token.
    Returns response with curr_user_id and curr_user_role.
    If token not valid return response with error.
    """
    token = token.json.get('token')
    response = await authorized(token)
    return response


async def generate_access_token(user_id, user_role):
    """
    Local function to generate JWT access token.
    Get user_id and user_role.
    Return access token.
    """
    payload = {
        'user_id': user_id,
        'role': user_role,
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    access_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
    return access_token


async def generate_refresh_token():
    """
    Local function to generate JWT refresh token.
    Return refresh token.
    """
    refresh_token = str(binascii.hexlify(os.urandom(24)), "utf-8")
    return refresh_token


@app.post('/auth/refresh-token')
async def refresh_tokens(request):
    """
    Refresh JWT tokens.
    Get request with refresh_token.
    Return JSON response with user_id, access_token and refresh_token.
    If find verification or security errors, return response with error.
    """
    db_session = DBSession()
    refresh_token = request.json.get('token')

    # Get session by refresh_token
    session = db_session.query(Session).filter_by(refresh_token=refresh_token).first()
    if not session:
        return json({"error": "AuthenticationFailed"}, status=401)
    user = db_session.query(User).filter_by(user_id=session.user_id).first()

    # Remove session from table
    db_session.query(Session).filter_by(refresh_token=refresh_token).delete()

    # Check refresh session
    expires_in = datetime.strptime(session.expires_in, '%Y-%m-%d  %H:%M:%S.%f')
    if expires_in < datetime.utcnow():
        return json({"error": "Token expired"}, status=401)
    if request.ip != session.ip:
        return json({"error": "Invalid refresh session"}, status=401)

    new_refresh_token = await generate_refresh_token()
    session = Session(user.user_id, new_refresh_token,
                      str(datetime.utcnow() + timedelta(seconds=JWT_EXP_REFRESH_DELTA_SECONDS)), request.ip)

    # Add new session to DB
    db_session.add(session)
    db_session.commit()

    # Generate new access token
    access_token = await generate_access_token(user.user_id, user.role)

    return json({'user_id': session.user_id, 'access_token': access_token.decode('utf-8'),
                 'refresh_token': new_refresh_token})


@app.post("/user/auth")
async def login(request):
    """
    Authenticate user.
    Get request with username and password.
    Create new session.
    Return JSON response with user_id, access_token and refresh_token.
    If find verification errors, raise server error.
    """
    db_session = DBSession()
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    ip = request.ip

    if not username or not password:
        raise ServerError("AuthenticationFailed", status_code=401)
    user = db_session.query(User).filter_by(username=username).first()

    if user is None:
        raise ServerError("AuthenticationFailed", status_code=401)

    if not user.match_password:
        raise ServerError("AuthenticationFailed", status_code=401)

    # Generate refresh token
    refresh_token = await generate_refresh_token()

    # Check user sessions
    user_sessions = db_session.query(Session).filter_by(user_id=user.user_id)
    session_count = user_sessions.count()
    if session_count >= 5:
        db_session.query(Session).filter_by(user_id=user.user_id).delete()
    for session in user_sessions:
        if session.ip == ip:
            db_session.query(Session).filter_by(ip=ip).delete()

    session = Session(user.user_id, refresh_token,
                      str(datetime.utcnow() + timedelta(seconds=JWT_EXP_REFRESH_DELTA_SECONDS)), ip)

    # Add session to DB
    db_session.add(session)
    db_session.commit()

    access_token = await generate_access_token(user.user_id, user.role)

    return json({'user_id': user.user_id, 'access_token': access_token.decode('utf-8'),
                 'refresh_token': refresh_token})


@app.post("/user/registry")
async def registry(request):
    """
    Register new user.
    Get request with user parameters: user_id, username, password, email, role.
    Return response with code 200.
    If parameters are wrong, or user already exist, raise server error.
    """
    db_session = DBSession()
    user_id = request.json.get("user_id", None)
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    email = request.json.get("email", None)
    role = request.json.get("role", None)

    if not user_id or not username or not password:
        raise ServerError("Bad request", status_code=400)
    if not role:
        role = "user"
    if db_session.query(User).filter_by(username=username).first():
        raise ServerError("User already exist", status_code=400)

    user = User(username, password, email, role)

    # Add user to DB
    db_session.add(user)
    db_session.commit()

    return json({}, status=201)


@app.get('/user/<user_id:int>')
async def get_user(request, user_id):
    """
    Show information about user and user offers.
    Get access token and user_id.
    Return JSON response with information with user and offers parameters.
    On authentication errors raise server error.
    """
    db_session = DBSession()

    # Authorization
    token = request.headers.get('Authorization', None)
    if token:
        auth_response = await authorized(token, local=True)
        curr_user_id = auth_response.get('curr_user_id')
        curr_user_role = auth_response.get('curr_user_role')
    else:
        raise ServerError("Token required", status_code=401)

    # Check user
    user = db_session.query(User).filter_by(user_id=user_id).first()
    if not user:
        raise ServerError("User not found", status_code=404)

    # Access rights resolve
    if user_id != curr_user_id and curr_user_role != "admin":
        raise ServerError("Forbidden", status_code=403)

    user_response = user.to_dict()
    data = {'user_id': user_id}
    offer_request = await send_request(data, 'offer', header={'authorization': token})
    response = {'user': user_response, 'offers': offer_request}
    return json(response)


@app.post('/user/verify')
async def verify_user(request):
    """
    Verify existence of user in database.
    Get user_id.
    Return JSON response with verify flag.
    """
    db_session = DBSession()
    user_id = request.json.get('user_id')
    user = db_session.query(User).filter_by(user_id=user_id).first()
    if user:
        response = json({'verify': True})
    else:
        response = json({'verify': False})
    return response


async def send_request(data, endpoint, header=None):
    """
    Simple client to send requests.
    Get data, endpoint and header.
    Return response dict.
    """
    server = "http://localhost"
    endpoints = {
        'offer': {'path': '/offer', 'port': ':8080'}
    }
    endpoint = endpoints.get(endpoint)
    if endpoint:
        path = endpoint.get('path')
        port = endpoint.get('port')
        address = server + port + path
    else:
        raise ServerError("Internal Server Error", status_code=500)
    data = j.dumps(data)
    async with httpx.AsyncClient() as client:
        if header:
            request = await client.post(address, data=data, headers=header)
        else:
            request = await client.post(address, data=data)
    if request.status_code != 200:
        auth_response = request.json()
        text = auth_response.get('error')
        if not text:
            raise ServerError("Internal Server Error", status_code=500)
        raise ServerError(text, status_code=request.status_code)
    response = request.json()
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, workers=os.cpu_count())
