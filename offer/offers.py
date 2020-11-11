import os
import json as j

import httpx
from sanic import Sanic
from sanic.response import json
from sanic.exceptions import ServerError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from offer_models import Offer

app = Sanic("offer_service")

engine = create_engine('sqlite:///offers.db')
DBSession = sessionmaker(bind=engine)


async def authorization(request):
    """
    Local function to authorize user by token.
    Get request with token.
    Return JSON response with curr_user_id and curr_user_role.
    If token not valid return response with error.
    """
    token = request.headers.get('Authorization', None)
    if token:
        data = {'token': token}
        auth_response = await send_request(data, 'auth')
        curr_user_id = auth_response.get('curr_user_id')
        curr_user_role = auth_response.get('curr_user_role')
        return {'curr_user_id': curr_user_id, 'curr_user_role': curr_user_role}
    else:
        return json({'error': "Token required"}, status=401)


@app.post("/offer/create")
async def create_offer(request):
    """
    Create new offer.
    Get request with token, user_id, title and text.
    Return response with code 200.
    If parameters are wrong or authentication error, raise server error.
    """
    db_session = DBSession()

    # Authorization
    data = await authorization(request)
    curr_user_id = data.get('curr_user_id')
    curr_user_role = data.get('curr_user_role')

    user_id = request.json.get('user_id')
    title = request.json.get('title')
    text = request.json.get('text')

    # Check request
    if not user_id or not title or not text:
        return json({'error': "Bad request"}, status=400)
    verify = await send_request({'user_id': user_id}, 'verify_user')
    if not verify.get('verify'):
        return json({'error': "Bad request"}, status=400)
    if not isinstance(title, str) or not isinstance(text, str):
        return json({'error': "Bad request"}, status=400)

    # Access rights resolve
    if user_id != curr_user_id and curr_user_role != "admin":
        return json({'error': "Forbidden"}, status=403)

    offer = Offer(user_id, title, text)

    # Add offer to DB
    db_session.add(offer)
    db_session.commit()
    return json({}, status=201)


@app.post("/offer")
async def get_offer(request):
    """
    Show information about offers.
    Get request with offer_id or user_id.
    If get offer_id show information about offer.
    If get user_id show information about user offers.
    Return JSON response with offer_id, user_id, title and text.
    If user_id return JSON response with dict of offer_id and offer information for each offer.
    If parameters are wrong or authentication error, raise server error.
    """
    db_session = DBSession()

    # Authorization
    data = await authorization(request)
    curr_user_id = data.get('curr_user_id')
    curr_user_role = data.get('curr_user_role')

    offer_id = request.json.get('offer_id')
    user_id = request.json.get('user_id')

    if not user_id and not offer_id:
        return json({'error': "Bad request"}, status=400)

    if offer_id:
        offer = db_session.query(Offer).filter_by(offer_id=offer_id).first()
        if not offer:
            return json({'error': "Bad request"}, status=400)

        # Access rights resolve
        if offer.user_id != curr_user_id and curr_user_role != "admin":
            return json({'error': "Forbidden"}, status=403)

        return json(offer.to_dict(), status=200)

    if user_id:
        # Access rights resolve
        if user_id != curr_user_id and curr_user_role != "admin":
            return json({'error': "Forbidden"}, status=403)

        user_offers = db_session.query(Offer).filter_by(user_id=user_id)
        response = {o.offer_id: o.to_dict() for o in user_offers}
        return json(response, status=200)


async def send_request(data, endpoint, header=None):
    """
    Simple client to send requests.
    Get data, endpoint and header.
    Return response dict.
    """
    server = "http://localhost"
    endpoints = {
        'auth': {'path': '/auth', 'port': ':8000'},
        'verify_user': {'path': '/user/verify', 'port': ':8000'}
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
    app.run(host="127.0.0.1", port=8080, workers=os.cpu_count())
