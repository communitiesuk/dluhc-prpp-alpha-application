import os
import botocore
from requests import codes
from flask import request, session
from flask_restful import Resource
from marshmallow import ValidationError
from src.auth.authentication import Authenticator
from src.auth.user_management import UserManager
from src.common import app_logger
from src.security.security import verify_token
from src.schemas.user_schema import (
    AgentSchema,
    LandlordSchema,
    LoginSchema,
    User,
    UserSchema,
    UserType,
    ChangeUsernameSchema,
    ChangePasswordSchema,
)
import src.common.error_messages as error_messages

logger = app_logger.logging.getLogger(__name__)

NO_DATA_PROVIDED_ERROR_MESSAGE = "No input data provided."

username_schema = ChangeUsernameSchema()
change_password_schema = ChangePasswordSchema()

TOTP_ATTEMPT_LIMIT = os.getenv("TOTP_ATTEMPT_LIMIT", 3)


class UserRegister(Resource):
    """Manages the user registration API."""

    @classmethod
    def post(cls):
        json_data = request.get_json()

        if not json_data:
            return {"message": NO_DATA_PROVIDED_ERROR_MESSAGE}, codes.bad_request

        user_pool_id = None

        client_id = os.getenv("CLIENT_ID", "")
        user_pool_id = os.getenv("USERPOOL_ID", "")

        pool_name = os.getenv("USERPOOL_NAME", "")

        auth = Authenticator(client_id=client_id, user_pool_id=user_pool_id)

        json_data["user_type"] = UserType.USER

        try:
            json_data["pool_name"] = pool_name

            # UserSchema doesn't accept client_id and errors if we pass it in
            try:
                json_data.pop("client_id")
            except Exception as e:
                logger.debug(f"{e}: No client_id")

            user = UserSchema()
            data = user.load(data=json_data)
            user_model = User(data=data)

            response = auth.sign_up(user_model)
            logger.debug(response)
            return response

        except ValidationError as e:
            return e.messages, codes.unprocessable_entity
        except ValueError as e:
            logger.error("ValueError={}".format(str(e)))
            return {"message": f"{e}"}, codes.bad_request


class UserLogin(Resource):
    """Manages the user authentication API. 'MFA_SETUP'|| 'SOFTWARE_TOKEN_MFA'"""

    @classmethod
    def post(cls):
        json_data = request.get_json()

        try:
            json_data = json_data["userObj"]
        except Exception as e:
            logger.debug(e)
            logger.debug("No user object received.")

        if not json_data:
            return {"message": NO_DATA_PROVIDED_ERROR_MESSAGE}, codes.bad_request
        try:
            user = LoginSchema()
            data = user.load(data=json_data)
            logger.debug(data)
            username = format(data["email"])

            password = format(data["password"])
            redirect_uri = format(data["redirect_uri"])

            auth = Authenticator(
                user_pool_id=os.getenv("USERPOOL_ID"), client_id=os.getenv("CLIENT_ID")
            )
            response = auth.login(
                username=username, password=password, redirect_uri=redirect_uri
            )

            session["attempts"] = TOTP_ATTEMPT_LIMIT

            return response

        except ValidationError as e:
            return e.messages, codes.unprocessable_entity
        except Exception as e:
            logger.debug(e)
            return {
                "message": error_messages.UNPROCESSABLE_ENTITY
            }, codes.unprocessable_entity


class VerifyTOTP(Resource):
    """Manages the user first MFA verify totp verification API."""

    @classmethod
    def post(cls):
        json_data = request.get_json()

        if not json_data:
            return {"message": NO_DATA_PROVIDED_ERROR_MESSAGE}, codes.bad_request

        try:
            data = json_data
            username = format(data["username"])
            access_token = session["access_token"]
            user_code = format(data["userCode"])

            try:
                user_pool = format(data["pool_name"])
            except Exception:
                user_pool = None

            try:
                client_id = format(data["client_id"])
            except Exception:
                client_id = None

            auth = Authenticator(user_pool_name=user_pool, client_id=client_id)
            response = auth.verify_totp(access_token=access_token, user_code=user_code)
            mfa_response = auth.set_mfa(username=username, active=True)  # NOQA: F841

            return response

        except ValidationError as e:
            return e.messages, codes.unprocessable_entity
        except Exception as e:
            logger.debug(e)
            return {
                "message": error_messages.UNPROCESSABLE_ENTITY
            }, codes.unprocessable_entity


class ConfirmTOTP(Resource):
    """Manages the user totp verification API."""

    @classmethod
    def post(cls):
        json_data = request.get_json()

        if session.get("attempts", 0) <= 0:
            return {
                "message": "Too many attempts or user not passed login credentials."
            }, 429

        try:
            session["attempts"] -= 1
        except Exception:
            logger.error("No session cookie")

        if not json_data:
            return {"message": NO_DATA_PROVIDED_ERROR_MESSAGE}, codes.bad_request

        try:
            data = json_data
            username = format(data["username"])
            s = format(data["session"])
            user_code = format(data["userCode"])

            try:
                user_pool = format(data["pool_name"])
            except Exception:
                user_pool = None

            try:
                client_id = format(data["client_id"])
            except Exception:
                client_id = None

            auth = Authenticator(user_pool_name=user_pool, client_id=client_id)
            response = auth.confirm_totp(
                username=username, _session=s, user_code=user_code
            )

            return response

        except ValidationError as e:
            return e.messages, codes.unprocessable_entity

        except Exception as e:
            logger.debug(e)
            return {
                "message": error_messages.UNPROCESSABLE_ENTITY
            }, codes.unprocessable_entity


class Verify(Resource):
    """Manages the confirm user verification API."""

    @classmethod
    def post(cls):
        json_data = request.get_json()

        if not json_data:
            return {"message": NO_DATA_PROVIDED_ERROR_MESSAGE}, codes.bad_request

        try:
            data = json_data
            username = format(data["username"])
            user_code = format(data["code"])

            try:
                user_pool = format(data["pool_name"])
            except Exception:
                user_pool = None

            try:
                client_id = format(data["client_id"])
            except Exception:
                client_id = None

            auth = Authenticator(user_pool_name=user_pool, client_id=client_id)
            response = auth.confirm_sign_up(username=username, code=user_code)

            return response

        except Exception as e:
            logger.debug(e)
            return {
                "message": error_messages.UNPROCESSABLE_ENTITY
            }, codes.unprocessable_entity


class ForgotPassword(Resource):
    """Manages the initial password forgot code request."""

    @classmethod
    def post(cls):
        json_data = request.get_json()

        if not json_data:
            return {"message": NO_DATA_PROVIDED_ERROR_MESSAGE}, codes.bad_request

        try:
            data = json_data
            username = format(data["username"])
            client_id = format(data["client_id"])

            auth = Authenticator(
                client_id=client_id, user_pool_id=os.getenv("USERPOOL_ID")
            )

            response = auth.forgot_password(username=username)

            return response

        except Exception as e:
            logger.debug(e)
            return {
                "message": error_messages.UNPROCESSABLE_ENTITY
            }, codes.unprocessable_entity


class ResetPassword(Resource):
    """Manages the confirmation for password reset."""

    @classmethod
    def post(cls):
        json_data = request.get_json()

        if not json_data:
            return {"message": NO_DATA_PROVIDED_ERROR_MESSAGE}, codes.bad_request

        try:
            data = json_data
            username = format(data["username"])
            password = format(data["password"])
            user_code = format(data["code"])

            client_id = os.getenv("CLIENT_ID")

            auth = Authenticator(client_id=client_id)
            response = auth.confirm_forgot_password(
                username=username, password=password, code=user_code
            )
            return response

        except Exception as e:
            logger.debug(e)
            return {
                "message": error_messages.UNPROCESSABLE_ENTITY
            }, codes.unprocessable_entity


class ChangePassword(Resource):
    """Manages changing password for user given old password"""

    @classmethod
    def post(cls):
        json_data = request.get_json()

        if not json_data:
            return {"message": NO_DATA_PROVIDED_ERROR_MESSAGE}, codes.bad_request

        try:
            data = change_password_schema.load(data=json_data)
            username = data["username"]
            old_password = data["old_password"]
            new_password = data["new_password"]

            pool_id = os.getenv("USERPOOL_ID", "")
            client_id = os.getenv("CLIENT_ID", "")

            auth = Authenticator(user_pool_id=pool_id, client_id=client_id)

            response = auth.change_password(
                username=username,
                old_password=old_password,
                new_password=new_password,
            )
            return response

        except Exception:
            return {
                "message": error_messages.UNPROCESSABLE_ENTITY
            }, codes.unprocessable_entity
