from flask import redirect, session, request
from flask_restful import Resource
from app.src.common import app_logger

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


private_key = os.getenv("private_key")

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

            print(session["access_token"])

            print({"message": "Received Token"})

            # validate token
            return redirect(
                f"{GOV_UK_APP}",
                code=302,
            )

        except Exception as e:
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
