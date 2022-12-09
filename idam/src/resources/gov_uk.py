from flask import redirect, session, request
from flask_restful import Resource
from src.common import app_logger

import os
import json
import random
import requests
import jwt
import time

from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = app_logger.logging.getLogger(__name__)

GOV_UK_AUTHORIZE_URL = "https://oidc.integration.account.gov.uk/authorize"
GOV_UK_DISCOVERY_URL = (
    "https://oidc.integration.account.gov.uk/.well-known/openid-configuration"
)
GOV_UK_LOGOUT_URL = "https://oidc.integration.account.gov.uk/logout"
GOV_UK_LOGIN_URL = "https://oidc.integration.account.gov.uk/login"
GOV_UK_REGISTER_URL = "https://oidc.integration.account.gov.uk/connect/register"
GOV_UK_TOKEN_URL = "https://oidc.integration.account.gov.uk/token"
GOV_UK_USER_INFO_URL = "https://oidc.integration.account.gov.uk/userinfo"
GOV_UK_PASSPORT_URL = "https://oidc.integration.account.gov.uk/logout"
GOV_UK_DRIVING_LICENSE_URL = "https://oidc.integration.account.gov.uk/logout"

PRPP_LOGOUT_URL = "https://prpp-alpha.labs.zaizicloud.net/signout"
PRPP_REDIRECT_URL = "https://prpp-alpha.labs.zaizicloud.net/redirect"


GOV_UK_CLIENT_ID = "yNAEOJ-pvHUBHOz2Y9DyzgyeR2o"
GOV_UK_REDIRECT_URL = "https://prpp-alpha.labs.zaizicloud.net/redirect"
GOV_UK_APP = "https://app.prpp-alpha.labs.zaizicloud.net/"

GOV_UK_UI_LOCALES = "en"


UNAUTHORIZED_CLIENT_ID_ERROR_MSG = "Unauthorized client id."


private_key = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFcI6HhrXVNwf8
TUlnQ59IHmCPro4tGEFMzed53C1X/Zpbl2EneCElwrDg8zTHbvIzZ94dqA/lkWaJ
X5ctZeGaJBdKa2VI6LeuXZoCScrnXOwlN1rihoWcxCePjWzQCboVlSatE435Y/hB
JmmqCIbOoViwbPgrPvrhRknBYqJsmuEoYDqPCFch+f92NPxyLSXinNjbxB1d3ujn
k4ir5HXhm/Qt2ED77/2TJhL5tuDq0Tx+ypV6sT85JiAiwSUW7W0O1xrlnnsv5dYO
2Ibg6e+ve2sECQph2UKV4WAdgCeYnQYHRNl5oaO1W/TWBeo/4K7US1GIhWrn3PwS
2nXfesKFAgMBAAECggEAPMPZeeiBye836/S1ZKyxNvbybQYiB8rxPfwZA6453lzU
xt+eLRGR0hdLbNAtLDv/Gsca2zHAQr0vO5RJ6NT0TAZTjLnk4D2PWoDAR3gClJZK
r2GL/S+9q3PLYSj7lkOIG+BdmOLtzRVxcEusNYKOSsXpj9LZxiWJ/Q8u3+/FYXr2
2pUpSrsAlYIZvC9EeDyRe1JpzSkEF/dr4+OpbM9Q60k/d/ERHzdsykY3v+Jwl+fx
vUCxLYEUZdB6q5MmM6weSmUESUSrlFYbwhEvZCaEBZIRdjBkYw/5AQA4vFPgZtj0
0KXxVxcnkg8086SlQaCLK+yscDrqkFgfZ7lVtxz6+QKBgQDpKgjTw6IqPEkrtHzJ
f9Z4+Hjiu8+yQ3BrUoV9kIexB+6nKSx3H/tWZWRte6EZkkaoRrBFjtE+7PeOoq1k
ifgvAj4PNJd4fQqZ0sXXRoFP2X3MYfe/iLrL0knUiEM+6WecfXbdLajjzGwE+oas
2AQpcBr0OJ3ODYyi4quWe55M7wKBgQDYxtNuNUXlNKcDWTms+ZXVwl1dxikMotPG
hRgHMRT13A+ausvPVq53LlPVfiiok2aJseQPhONNZ054XoWAcetxzRhjxWyWZZC7
OtEzlY+9QVBo8TEq6/MU2D07QqE+WNWQ0A7+pPZn6andFnG/2hFPZKXWj6cZ7ifW
nRjyoCpPywKBgQCmNRWXxuQJUXIjWoR9qsg68XxSu+ihPVuc1XVc/bMMagggVsRg
ooaqnppJRRCgxtnhSIqM+vKD9a2+mo4ZlhQ5hlKwyh+TfycYYdwvyg2R2wrGr6tI
eHIXqu6ANyYgaYc3UWRy5AJ5aBY0MlXgThghZc2A+/7ZjGUNE6GXIsXENwKBgBGg
cTbH7CwMEPyLt83h6ZYdHNxwLYxSfSfqUJ7dFdg8EaTCRapRYRRd1wFIJeQ3QCI4
LdQ5OQZlPRM6lF5yZPO2+qG6Pu8nyRIAYVxxb+OyuOgfnKDh2L08LBZyf4wDSzJg
SKfaIBMpA9/vYEZ6Y+fxxi5hNfQ80k54Lbwk2+vrAoGAeiWL+yoBcILjxsDWdUN3
SZFA4RLDd15B3YBAhKJmZesHK18DKrovYncZ14J/E0MbIPvro4iI1PIvNvIdqGK3
xdYjP0ZPkSFcc455390F6LB4UqCoyUpkWdyXOqhDOeAM527XFOag4RJIufPfRyfs
/5qHpX5xNYRUzaDslsj+VIg=
-----END PRIVATE KEY-----
"""


def generate_nonce(length=8):
    """Generate pseudorandom number."""
    return "".join([str(random.randint(0, 9)) for i in range(length)])


def generate_state(length=8):
    """Generate pseudorandom state value."""
    return "".join([str(random.choice(0, 9)) for i in range(length)])


class GovUKAuthorizeResource(Resource):
    """Manages Gov UK Sign In Flow."""

    @classmethod
    def get(cls):

        try:
            host = GOV_UK_AUTHORIZE_URL
            response_type = "code"
            scope = "openid"
            client_id = GOV_UK_CLIENT_ID
            state = "STATE"
            redirect_uri = GOV_UK_REDIRECT_URL
            nonce = generate_nonce()
            ui_locales = GOV_UK_UI_LOCALES

            return redirect(
                f"{host}?response_type={response_type}&client_id={client_id}&scope={scope}&state={state}&redirect_uri={redirect_uri}&nonce={nonce}&ui_locales={ui_locales}",
                code=302,
            )
        except Exception as e:
            print("Error authorizing", e)


class GovUKRedirectResource(Resource):
    """Manages Gov UK Redirect."""

    @classmethod
    def get(cls):

        print("request")
        print(request)

        if not request.args:
            return {"message": "NO DATA"}, 400

        logger.debug(request.args)

        base_url = os.getenv("IDAM_UI_BASE_URL", None)
        if not base_url:
            return {"message": "Invalid IDAM UI base_url"}, 400

        try:
            session["authorization_code"] = request.args.get("code")

            payload = {
                "aud": "https://oidc.integration.account.gov.uk/token",
                "iss": GOV_UK_CLIENT_ID,
                "sub": GOV_UK_CLIENT_ID,
                "exp": int(time.time() + 300),
                "jti": generate_nonce(),
                "iat": int(time.time()),
            }

            token = jwt.encode(
                {
                    "aud": "https://oidc.integration.account.gov.uk/token",
                    "iss": GOV_UK_CLIENT_ID,
                    "sub": GOV_UK_CLIENT_ID,
                    "exp": int(time.time() + 300),
                    "jti": generate_nonce(),
                    "iat": int(time.time()),
                },
                key=private_key,
                algorithm="RS256",
            )

            host = GOV_UK_TOKEN_URL
            grant_type = "authorization_code"
            redirect_uri = PRPP_REDIRECT_URL
            client_assertion = token.decode("utf-8")
            client_assertion_type = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )

            code = session["authorization_code"]

            payload = {
                "grant_type": grant_type,
                "redirect_uri": redirect_uri,
                "code": code,
                "client_assertion": client_assertion,
                "client_assertion_type": client_assertion_type,
            }

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }

            response = requests.request("POST", url=host, headers=headers, data=payload)

            access_token = response.json().get("access_token")
            id_token = response.json().get("id_token")
            token_type = response.json().get("token_type")
            expires_in = response.json().get("expires_in")

            session["access_token"] = access_token
            session["id_token"] = id_token
            session["token_type"] = token_type
            session["expires_in"] = expires_in
            session["expires_at"] = time.time() + expires_in

            print({"message": "Received Token"})

            # validate token
            return redirect(
                f"{GOV_UK_APP}",
                code=302,
            )

        except Exception as e:
            logger.debug(f"Error: {e}")
            return {"message": f"Error: {e}"}, 403


class GovUKDiscoveryResource(Resource):
    """Manages Gov UK Discovery Service."""

    @classmethod
    def get(cls):

        try:
            host = GOV_UK_DISCOVERY_URL

            return redirect(
                f"{host}",
                code=302,
            )

        except Exception as e:
            print("Error authorizing", e)


class GovUKLogoutResource(Resource):
    """Manages Gov UK Logout Flow."""

    @classmethod
    def get(cls):

        try:
            host = GOV_UK_LOGOUT_URL
            id_token_hint = session["id_token"]
            post_logout_redirect_uri = PRPP_LOGOUT_URL
            state = generate_nonce()

            return redirect(
                f"{host}?id_token_hint={id_token_hint}&post_logout_redirect_uri={post_logout_redirect_uri}&state={state}",
                code=302,
            )
        except Exception as e:
            print("Logout Error", e)


class GovUKLoginResource(Resource):
    """Manages Gov UK Sign In Flow."""
    # TBD

    @classmethod
    def get(cls):

        try:
            host = GOV_UK_LOGIN_URL
            response_type = "code"
            scope = "openid"
            client_id = GOV_UK_CLIENT_ID
            state = "STATE"
            redirect_uri = GOV_UK_REDIRECT_URL
            nonce = generate_nonce()
            ui_locales = GOV_UK_UI_LOCALES

            return redirect(
                f"{host}?response_type={response_type}&client_id={client_id}&scope={scope}&state={state}&redirect_uri={redirect_uri}&nonce={nonce}&ui_locales={ui_locales}",
                code=302,
            )
        except Exception as e:
            print("Error authorizing", e)


class GovUKUserInfoResource(Resource):
    """
    Manages Gov UK User Info Resource.
    Example Response
        {
            "sub": "b2d2d115-1d7e-4579-b9d6-f8e84f4f56ca",
            "email": "test@example.com",
            "email_verified": true,
            "phone": "01406946277",
            "phone_verified": true,
            "updated_at":1311280970
            }
    """

    @classmethod
    def get(cls):

        try:
            host = GOV_UK_USER_INFO_URL
            payload = {}
            headers = {
                "Authorization": f"Bearer {session['access_token']}",
            }

            response = requests.request("GET", url=host, headers=headers, data=payload)

            session["sub"] = response.json().get("sub")

            return {"Sub": session["sub"]}, 200

        except Exception as e:
            print("Error authorizing", e)


class GovUKTokenResource(Resource):
    """Manages Gov UK Token Flow."""

    @classmethod
    def get(cls):

        payload = {
            "aud": "https://oidc.integration.account.gov.uk/token",
            "iss": GOV_UK_CLIENT_ID,
            "sub": GOV_UK_CLIENT_ID,
            "exp": generate_nonce(),
            "jti": int(time.time() + 300),
            "iat": int(time.time()),
        }

        token = jwt.encode(
            {
                "aud": "https://oidc.integration.account.gov.uk/token",
                "iss": GOV_UK_CLIENT_ID,
                "sub": GOV_UK_CLIENT_ID,
                "exp": int(time.time() + 300),
                "jti": generate_nonce(),
                "iat": int(time.time()),
            },
            key=private_key,
            algorithm="RS256",
        )

        # with open("../../keys/private_key.pem", "rb") as private_key:
        #     key_data = private_key.read()
        #     token = jwt.encode(payload=payload, key=key_data)

        try:
            host = GOV_UK_TOKEN_URL
            grant_type = "authorization_code"
            redirect_uri = session["redirect_uri"]
            client_assertion = token
            client_assertion_type = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            code = session["authorization_code"]

            return redirect(
                f"{host}?response_type={response_type}&client_id={client_id}&scope={scope}&state={state}&redirect_uri={redirect_uri}&nonce={nonce}&ui_locales={ui_locales}",
                code=302,
            )
        except Exception as e:
            print("Error authorizing", e)


class GovUKRegisterResource(Resource):
    """Manages Gov UK Sign In Flow."""
    # TBD

    @classmethod
    def get(cls):

        try:
            host = GOV_UK_REGISTER_URL
            response_type = "code"
            scope = "openid"
            client_id = GOV_UK_CLIENT_ID
            state = "STATE"
            redirect_uri = GOV_UK_REDIRECT_URL
            nonce = generate_nonce()
            ui_locales = GOV_UK_UI_LOCALES

            return redirect(
                f"{host}?response_type={response_type}&client_id={client_id}&scope={scope}&state={state}&redirect_uri={redirect_uri}&nonce={nonce}&ui_locales={ui_locales}",
                code=302,
            )
        except Exception as e:
            print("Error authorizing", e)


class GovUKSignoutResource(Resource):
    """Manages Gov UK Sign Out Flow."""
    # TBD

    @classmethod
    def get(cls):

        try:
            host = GOV_UK_LOGIN_URL
            response_type = "code"
            scope = "openid"
            client_id = GOV_UK_CLIENT_ID
            state = "STATE"
            redirect_uri = GOV_UK_REDIRECT_URL
            nonce = generate_nonce()
            ui_locales = GOV_UK_UI_LOCALES

            return redirect(
                f"{host}?response_type={response_type}&client_id={client_id}&scope={scope}&state={state}&redirect_uri={redirect_uri}&nonce={nonce}&ui_locales={ui_locales}",
                code=302,
            )
        except Exception as e:
            print("Error authorizing", e)
