import os

import jwt
from flask import request
from src.auth.authentication import Authenticator
from src.common.app_logger import logging
from werkzeug.security import safe_str_cmp

READ_ONLY = "R"
READ_WRITE = "RW"

logger = logging.getLogger(__name__)

API_KEY = os.getenv("IDAM_API_KEY", "")
SECRET = os.getenv("JWT_SECRET_KEY", "")

INVALID_API_KEY_MSG = "Unauthorized."


def api_key_admin_only(func):
    def check_api(*args, **kwargs):
        logger.debug(args)
        logger.debug(kwargs)
        logger.debug(request.headers)

        encoded_jwt = request.headers.get("X-API-KEY", "")

        try:
            decoded_jwt = jwt.decode(encoded_jwt, SECRET, algorithms=["HS256"])
            logger.debug(decoded_jwt)
            access_type = decoded_jwt.get("access_type", "")
            if not safe_str_cmp(access_type, READ_WRITE):
                return {"message": INVALID_API_KEY_MSG}, 401
        except Exception:
            return {"message": INVALID_API_KEY_MSG}, 401

        return func(*args, **kwargs)

    check_api.__name__ = func.__name__
    return check_api


def api_key_all(func):
    def check_api(*args, **kwargs):
        logger.debug(args)
        logger.debug(kwargs)
        logger.debug(request.headers)

        encoded_jwt = request.headers.get("X-API-KEY", "")

        try:
            decoded_jwt = jwt.decode(encoded_jwt, SECRET, algorithms=["HS256"])
            logger.debug(decoded_jwt)
            access_type = decoded_jwt.get("access_type", "")
            logger.debug("access_type={}".format(access_type))
            if not safe_str_cmp(access_type, READ_ONLY) and not safe_str_cmp(
                access_type, READ_WRITE
            ):
                return {"message": INVALID_API_KEY_MSG}, 401
        except Exception:
            return {"message": INVALID_API_KEY_MSG}, 401

        return func(*args, **kwargs)

    check_api.__name__ = func.__name__
    return check_api


def verify_token(
    cognito_client: object = None, client_id: str = None, access_token: str = None, userpool_id: str = None
) -> tuple:
    logger.debug("verify_token")


    # Create Authenticator
    if cognito_client:
        auth = Authenticator(
            client=cognito_client,
            client_id=client_id,
            user_pool_id=userpool_id,
        )
    else:
        auth = Authenticator(client_id=client_id, user_pool_id=userpool_id)

    payload, status = auth.get_user(access_token=access_token)

    if status == 200:
        return {
            "message": "Token verified ok.",
            "user_groups": payload["user_groups"],
        }, 200
    else:
        return {"message": "Token verify failed."}, 401


def access_token_required(func):
    def check_token(*args, **kwargs):
        logger.debug(args)
        logger.debug(kwargs)
        logger.debug(request.headers)

        try:
            headers = request.headers
        except Exception as e:
            logger.debug(e)
            return {"message": "No headers exception."}, 500

        try:
            bearer_token = headers["Authorization"].split(" ")
        except Exception as e:
            logger.debug(e)
            return {"message": "Error in the authorization header."}, 400

        logger.debug(headers)
        logger.debug(bearer_token)

        client_id = request.args.get("client_id", None)

        _, status_code = verify_token(client_id=client_id, access_token=bearer_token[1])

        if status_code != 200:
            return {"message": "Unauthorized."}, 401

        return func(*args, **kwargs)

    check_token.__name__ = func.__name__
    return check_token
