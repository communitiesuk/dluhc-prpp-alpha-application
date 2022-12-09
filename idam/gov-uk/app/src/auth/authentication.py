from http import client
import os
import uuid
import time
from datetime import datetime, tzinfo, timedelta
import boto3
import botocore
import requests
from flask import redirect, session
from marshmallow import ValidationError
from pycognito.aws_srp import AWSSRP
from pycognito.exceptions import ForceChangePasswordException
from app.src.common import app_logger
from app.src.common.utils import idam_decode, idam_encode
from app.src.models.access_tokens import AccessModel
from app.src.schemas.access_schema import AccessSchema
from app.src.schemas.user_schema import UserType
import app.src.common.error_messages as error_messages

logger = app_logger.logging.getLogger(__name__)

access_schema = AccessSchema()

SERVER_ERROR_MESSAGE = error_messages.SERVER_ERROR_MESSAGE
INVALID_PARAMETER_MESSAGE = error_messages.INVALID_PARAMETER_MESSAGE
RESOURCE_NOT_FOUND_MESSAGE = error_messages.RESOURCE_NOT_FOUND_MESSAGE
INTERNAL_ERROR_MESSAGE = error_messages.INTERNAL_ERROR_MESSAGE
NOT_AUTHORIZED_MESSAGE = error_messages.NOT_AUTHORIZED_MESSAGE
TOO_MANY_REQUESTS_MESSAGE = error_messages.TOO_MANY_REQUESTS_MESSAGE
LIMIT_EXCEEDED_MESSAGE = error_messages.LIMIT_EXCEEDED_MESSAGE
USER_NOT_FOUND_MESSAGE = error_messages.USER_NOT_FOUND_MESSAGE

IDAM_BACKEND_CLIENT_NAME = "IDAM-BACKEND"
IDAM_BACKEND_NO_S_CLIENT_NAME = "IDAM-BACKEND-NO-SECRET"
COMPETITION_PLATFORM = "COMPETITION-PLATFORM"

MIN_PASSWORD_LEN = int(os.getenv("MIN_PASSWORD_LEN", 8))


class simple_utc(tzinfo):
    def tzname(self, **kwargs):
        return "UTC"

    def utcoffset(self, dt):
        return timedelta(0)


class Authenticator:
    """Manages the authentication interface with AWS Cognito

    Returns:
        object: Authentication Session
    """

    def __init__(
        self,
        client=None,
        user_pool_id=None,
        user_pool_name=None,
        client_id=None,
        fast=False,
    ):
        if not client:
            # Create the AWS session.  This session will then be
            # used to communicate with the AWS services.
            local_dev = os.getenv("LOCAL_DEV", True)
            if not local_dev:
                self.session = boto3.session.Session(
                    region_name=os.getenv("AWS_REGION_NAME", "")
                )
            else:  # LOCAL_DEV is set
                self.session = boto3.session.Session(
                    aws_access_key_id=os.getenv(
                        "AWS_ACCESS_KEY_ID", "ASIAT5K3PMBYCULWOV6I"
                    ),
                    aws_secret_access_key=os.getenv(
                        "AWS_SECRET_ACCESS_KEY",
                        "MbP5SRj29q+ccQKkW0cnfwMgOuTJlHA5ZH2IG7uD",
                    ),
                    aws_session_token=os.getenv(
                        "AWS_SESSION_TOKEN",
                        "FwoGZXIvYXdzECQaDPOfskCPqqMvxWU81iK5AX8OPOseWAECEtICefvRodmH+CtNZBL/MEJcdsG1gUR7fYkPsIKLe1eDaK96kc1CV6XVy643WRhh8HERKq957NoDY3yEwkH+nRf4OzEFDS5Y3PtisbEVV/41Cn5i1Xlj+LvSv/4h8V1L9UauNceulfMGpuSQZrs+MrlneSqUBfOLQI3neZqDSFrAvauVnrTtQ+t0tRe+gW3wJJGRFtsQ1SuJk9ncCRj5j6EqPmTvhvZ442+MTDxU3zMsKP3f1JsGMi3eBEP1Ma/kcVe4sszVdHfnjLcz7ybMQRG2lkaXYnHf4fiw/hppVk/yo2NYyQk=",
                    ),
                    region_name=os.getenv("AWS_REGION_NAME", "eu-west-2"),
                )

            # Now create a cognito client so that we can do cognito stuff.
            self.cognito_client = self.session.client("cognito-idp")
        else:
            self.cognito_client = client

        self.user_pool = os.getenv("USERPOOL_ID", "")

    def delete_user(self, username):
        """Deletes a cognito user."""
        try:
            response = self.cognito_client.admin_delete_user(
                UserPoolId=self.user_pool["Id"], Username=username
            )

            logger.debug(response)
            return {"message": "User deleted successfully!"}, requests.codes.ok

        except botocore.exceptions.ClientError as err:
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception:
            return {"message": SERVER_ERROR_MESSAGE}, requests.codes.bad_request

    def list_users(self):
        """Returns a list of cognito users."""
        return self.cognito_client.list_users(UserPoolId=self.user_pool["Id"])

    def sign_up(self, user):
        """Registers and creates a user.

        Args:
            user (User): A user class model

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        logger.debug("USER DUMP: {}".format(user))

        client_id = None
        user_attributes = [
            {"Name": "email", "Value": user.email},
        ]

        if user.user_type == "local":
            client_id = os.getenv("LOCAL_AUTHORITY_CLIENT_ID")
            userpool_id = os.getenv("LOCAL_USERPOOL_ID")
            pool_name = os.getenv("LOCAL_POOL_NAME")

        else:
            client_id = os.getenv("LOCAL_AUTHORITY_CLIENT_ID")
            userpool_id = os.getenv("AGENT_USERPOOL_ID")
            pool_name = os.getenv("AGENT_POOL_NAME")

        try:
            response = self.cognito_client.sign_up(
                ClientId=client_id,
                Username=user.username,
                Password=user.password,
                UserAttributes=user_attributes,
                ValidationData=[{"Name": "email", "Value": user.email}],
            )

            return {
                "message": "User created successfully pending confirmation.",
                "username": response["UserSub"],
            }, response["ResponseMetadata"]["HTTPStatusCode"]

        except botocore.exceptions.ClientError as err:
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug("Register error", e)
            return {
                "message": SERVER_ERROR_MESSAGE
            }

    def add_user_to_group(self, username, group_name):
        """Adds a user to a group.

        Args:
            username (string): Username.
            group_name (string): The name of the group to add the user to.

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        try:
            response = self.cognito_client.admin_add_user_to_group(
                UserPoolId=self.user_pool["Id"],
                Username=username,
                GroupName=group_name,
            )

            return {"message": "User added to group: {}.".format(group_name)}, response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]

        except botocore.exceptions.ClientError as err:
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception:
            return {
                "message": SERVER_ERROR_MESSAGE
            }, requests.codes.unprocessable_entity

    def set_mfa(self, username, active):
        try:
            pool_id = self.user_pool["Id"]
            response = self.cognito_client.admin_set_user_mfa_preference(
                Username=username,
                UserPoolId=pool_id,
                SoftwareTokenMfaSettings={"Enabled": active, "PreferredMfa": active},
            )
            try:
                self.cognito_client.admin_update_user_attributes(
                    UserPoolId=self.user_pool["Id"],
                    Username=username,
                    UserAttributes=[
                        {"Name": "custom:mfa_setup_complete", "Value": "1"}
                    ],
                )
            except botocore.exceptions.ClientError as err:
                logger.debug(err)
            except Exception as e:
                logger.debug(e)
            return {"message": "OK"}, response["ResponseMetadata"]["HTTPStatusCode"]

        except Exception as e:
            logger.error(e)
            return {"message": SERVER_ERROR_MESSAGE}, requests.codes.bad_request

    def login(
        self,
        username,
        password,
        account_type=None,
        userpool_id=None,
        client_id=None,
        srp_instance=None,
    ):
        """User Login

        Args:
            email (str): User email
            password (str): User password
            srp_instance (object): Secure Remote Password handler instance
            redirect_uri (str): The redirect uri

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """

        if account_type == "local":
            client_id = os.getenv("LOCAL_AUTHORITY_CLIENT_ID")
            userpool_id = os.getenv("LOCAL_USERPOOL_ID")

        else:
            client_id = os.getenv("AGENT_CLIENT_ID")
            userpool_id = os.getenv("AGENT_USERPOOL_ID")

        aws = AWSSRP(
            username=username,
            password=password,
            pool_id=userpool_id,
            client_id=client_id,
            client=self.cognito_client,
        )

        try:
            res = aws.authenticate_user()
            logger.debug("AUTHENTICATED")
        except ForceChangePasswordException:
            logger.debug(f"Force change password required.")
            return {
                "username": username,
                "challenge_name": "NEW_PASSWORD_REQUIRED",
            }, requests.codes.ok
        except Exception as e:
            logger.debug("Login error: ", e)
            return {"message": f"Error{e}"}, 400

        try:
            unique_code = str(uuid.uuid4())
            access_record = AccessModel.find_by_access_code(unique_code)
            if access_record:
                access_record.delete_from_db()
            # save session variables
            session["id"] = str(uuid.uuid4())
            session["access_token"] = idam_encode(
                res["AuthenticationResult"]["AccessToken"]
            )
            session["refresh_token"] = idam_encode(
                res["AuthenticationResult"]["RefreshToken"]
            )
            session["expiry"] = res["AuthenticationResult"]["ExpiresIn"]
            session["timestamp"] = time.time()
            session["pool_id"] = userpool_id
            session["client_id"] = client_id

            print("Session", session)
            print("Session", session["access_token"])
            print("Session", session["refresh_token"])
            print("Session", session["expiry"])

            access_record = access_schema.load(
                {
                    "access_code": unique_code,
                    "token_type": res["AuthenticationResult"]["TokenType"],
                    "expiry": res["AuthenticationResult"]["ExpiresIn"],
                    "access_token": res["AuthenticationResult"]["AccessToken"],
                    "refresh_token": res["AuthenticationResult"]["RefreshToken"],
                    "session_id": "",
                }
            )
            access_record = AccessModel(**access_record)
            access_record.save_to_db()
            print("Saved record", session["id"])
            logger.debug("Saved record", session["id"])
        except Exception as e:
            print("No access token in response", e)
            logger.debug(f"No access token in response: {e}")
        except botocore.exceptions.ClientError as err:
            logger.debug(f"{err.response['Error']['Message']}")

            # This exception handler is required to display a nice message to the user
            # if incorrect credentials.
            if err.response["Error"]["Code"] == "NotAuthorizedException":
                message = err.response["Error"]["Message"]
            elif err.response["Error"]["Code"] == "UserNotConfirmedException":
                message = "User is not confirmed."
            elif err.response["Error"]["Code"] == "UserNotFoundException":
                message = "Couldn't find your account."
            else:
                message = "Client Error."

            return {"message": message}, err.response["ResponseMetadata"][
                "HTTPStatusCode"
            ]
        except self.cognito_client.exceptions.NotAuthorizedException:
            logger.debug("Invalid username/password.")
            return {"message": "Unauthorized."}, requests.codes.bad_request
        except Exception as e:
            logger.debug(f"Error: {e}")
            return {"message": SERVER_ERROR_MESSAGE}, requests.codes.bad_request

        return res, 200

    def verify_totp(self, access_token, user_code):
        """Verifies TOTP

        Args:
            session (object): Session object
            user_code (str): AWS User Code

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        logger.debug("Verify TOTP")
        try:
            response = self.cognito_client.verify_software_token(
                AccessToken=access_token,
                UserCode=user_code,
            )
            return {"status": response["Status"]}, response["ResponseMetadata"][
                "HTTPStatusCode"
            ]
        except self.cognito_client.exceptions.CodeMismatchException:
            return {"message": "2FA code mismatch."}, requests.codes.bad_request
        except Exception as e:
            logger.debug(e)
            return {"message": SERVER_ERROR_MESSAGE}, requests.codes.bad_request

    def confirm_totp(self, username, _session, user_code):
        """MFA Verify procedure

        Args:
            username (str): The user's username.
            session (object): Session
            user_code (str): AWS User Code

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        logger.debug("Confirm TOTP")
        try:
            response = self.cognito_client.respond_to_auth_challenge(
                ClientId=self.user_pool["IdamClientNoSecret"]["ClientId"],
                ChallengeName="SOFTWARE_TOKEN_MFA",
                Session=_session,
                ChallengeResponses={
                    "USERNAME": username,
                    "SOFTWARE_TOKEN_MFA_CODE": user_code,
                },
            )

            if response["ResponseMetadata"]["HTTPStatusCode"] != requests.codes.ok:
                return {
                    "message": "Unknown error with authentication."
                }, requests.codes.unauthorized

            # store the token in the database so that we can have it retrieved via
            # a request on /api/token?code=unique_code.
            unique_code = str(uuid.uuid4())
            access_record = AccessModel.find_by_access_code(unique_code)
            if access_record:
                access_record.delete_from_db()

            try:
                session["id"] = str(uuid.uuid4())
                session["access_token"] = idam_encode(
                    response["AuthenticationResult"]["AccessToken"]
                )
                session["refresh_token"] = idam_encode(
                    response["AuthenticationResult"]["RefreshToken"]
                )
                session["expiry"] = response["AuthenticationResult"]["ExpiresIn"]
                session["timestamp"] = time.time()
                session["pool_id"] = self.user_pool["Id"]
                session["client_id"] = self.user_pool["IdamClientNoSecret"]["ClientId"]

                access_record = access_schema.load(
                    {
                        "access_code": unique_code,
                        "token_type": response["AuthenticationResult"]["TokenType"],
                        "expiry": response["AuthenticationResult"]["ExpiresIn"],
                        "access_token": response["AuthenticationResult"]["AccessToken"],
                        "refresh_token": response["AuthenticationResult"][
                            "RefreshToken"
                        ],
                        "session_id": _session,
                    }
                )
                access_record = AccessModel(**access_record)
                access_record.save_to_db()

            except ValidationError as e:
                logger.error(e)
                return {"message": SERVER_ERROR_MESSAGE}, requests.codes.bad_request
            except Exception as e:
                logger.error(e)
                return {
                    "message": SERVER_ERROR_MESSAGE
                }, requests.codes.unprocessable_entity

            return {"message": "User authenticated", "code": unique_code}, response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]

        except self.cognito_client.exceptions.CodeMismatchException:
            return {"message": "2FA code mismatch."}, requests.codes.bad_request
        except Exception as e:
            logger.error(e)
            return {"message": SERVER_ERROR_MESSAGE}, requests.codes.bad_request

    def confirm_sign_up(self, username, code):
        """Confirms user sign up.

        Args:
            username (str): Username
            code (str): Confirmation code

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        try:
            response = self.cognito_client.confirm_sign_up(
                ClientId=self.user_pool["IdamClientNoSecret"]["ClientId"],
                Username=username,
                ConfirmationCode=code,
            )

            try:
                self.cognito_client.admin_update_user_attributes(
                    UserPoolId=self.user_pool["Id"],
                    Username=username,
                    UserAttributes=[
                        {
                            "Name": "custom:verified_at",
                            "Value": datetime.utcnow()
                            .replace(tzinfo=simple_utc())
                            .isoformat(),
                        },
                        {
                            "Name": "custom:last_seen",
                            "Value": datetime.utcnow()
                            .replace(tzinfo=simple_utc())
                            .isoformat(),
                        },
                    ],
                )
            except Exception as e:
                logger.error(e)

            logger.debug(response)
            return {"username": username, "confirmed": "true"}, response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except botocore.exceptions.ClientError as err:
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.error(e)
            return {
                "message": SERVER_ERROR_MESSAGE
            }, requests.codes.unprocessable_entity

    def refresh_session(self, refresh_token=None, client_id=None, pool_id=None):
        if not refresh_token:
            return {"message": "Missing refresh token."}, requests.codes.bad_request
        else:
            refresh_token = idam_decode(refresh_token)

        try:
            response = self.cognito_client.admin_initiate_auth(
                UserPoolId=pool_id,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={"REFRESH_TOKEN": refresh_token},
                ClientId=client_id,
            )

            logger.debug("init_auth response: {}".format(response))

            if response["ResponseMetadata"]["HTTPStatusCode"] != requests.codes.ok:
                return {
                    "message": "Unknown error with token refresh."
                }, requests.codes.unauthorized

            result = response["AuthenticationResult"]

            # save in session
            session["access_token"] = idam_encode(result["AccessToken"])

            return {
                "token_type": result.get("TokenType", ""),
                "expiry": result.get("ExpiresIn", ""),
                "access_token": result.get("AccessToken", ""),
                "refresh_token": result.get("RefreshToken", ""),
            }, requests.codes.ok

        except botocore.exceptions.ClientError as err:
            logger.debug(f"{err.response['Error']['Message']}")
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug(e)
            return {"message": SERVER_ERROR_MESSAGE}, requests.codes.server_error

    def get_user(self, access_token):
        """Get user details

        Args:
            access_token (string): access token required to get user details.

        Returns:
            dict: user dictionary object.
        """
        logger.debug("get_user")
        try:
            # check to refresh tokens if expired
            try:
                response = self.cognito_client.get_user(AccessToken=access_token)
            except self.cognito_client.exceptions.NotAuthorizedException as e:
                logger.debug("Not authorized, request new tokens")
                if e.response["Error"]["Message"] == "Access Token has expired":
                    self.refresh_session(
                        refresh_token=session["refresh_token"],
                        client_id=session["client_id"],
                        pool_id=session["pool_id"],
                    )
                    access_token = idam_decode(session["access_token"])

            response = self.cognito_client.get_user(AccessToken=access_token)

            return response, requests.codes.ok
        except Exception as e:
            logger.error(e)
            return {
                "message": SERVER_ERROR_MESSAGE
            }, requests.codes.unprocessable_entity

    def admin_confirm_sign_up(self, username):
        """Confirms user sign up.

        Args:
            username (str): Username
            code (str): Confirmation code

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        logger.debug("admin_confirm_sign_up")
        try:
            response = self.cognito_client.admin_confirm_sign_up(
                UserPoolId=self.user_pool["Id"],
                Username=username,
            )
            return {"username": username, "confirmed": "true"}, response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except botocore.exceptions.ClientError as err:
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.error(e)
            return {
                "message": SERVER_ERROR_MESSAGE
            }, requests.codes.unprocessable_entity

    def forgot_password(self, username):
        """Requests forgot password code.

        Args:
            username (str): Username

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        logger.debug("forgot_password")
        try:
            response = self.cognito_client.forgot_password(
                ClientId=self.user_pool["IdamClientNoSecret"]["ClientId"],
                Username=username,
            )
            return {"username": username}, response["ResponseMetadata"][
                "HTTPStatusCode"
            ]
        except botocore.exceptions.ClientError as err:
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.error(e)
            return {
                "message": SERVER_ERROR_MESSAGE
            }, requests.codes.unprocessable_entity

    def confirm_forgot_password(self, username, password, code):
        """Confirms user password reset.

        Args:
            username (str): Username
            password (str): Password
            code (str): Confirmation code

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        logger.debug("confirm_forgot_password")
        try:
            if len(code) == 0:
                return {"message": "No code."}, requests.codes.bad_request
            if len(password) < MIN_PASSWORD_LEN:
                return {"message": "Invalid Password."}, requests.codes.bad_request
            response = self.cognito_client.confirm_forgot_password(
                ClientId=self.user_pool["IdamClientNoSecret"]["ClientId"],
                Username=username,
                Password=password,
                ConfirmationCode=code,
            )
            return {"username": username, "reset": "true"}, response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except botocore.exceptions.ClientError as err:
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.error(e)
            return {
                "message",
                SERVER_ERROR_MESSAGE,
            }, requests.codes.unprocessable_entity

    def change_password(self, username, old_password, new_password):
        """Changes user password.

        Args:
            username (str): Username
            old_password (str): User's old password
            new_password (str): User's new password

        Returns:
            tuple: Returns a dictionary object and an HTTP status code.
        """
        logger.debug("change_password")
        try:
            if len(new_password) < MIN_PASSWORD_LEN:
                return {"message": "Invalid Password."}, requests.codes.bad_request
            pool_id = self.user_pool["Id"]

            # We need to use the actual username for this, not the preferred_username.
            user_details = self.cognito_client.admin_get_user(
                UserPoolId=pool_id, Username=username.lower()
            )

            username = user_details["Username"]

            aws = AWSSRP(
                username=username.lower(),
                password=old_password,
                pool_id=pool_id,
                client_id=self.user_pool["CompetitionPlatform"]["ClientId"],
                client_secret=self.user_pool["CompetitionPlatform"]["ClientSecret"],
                client=self.cognito_client,
            )
            response = aws.set_new_password_challenge(new_password=new_password)
            return {"username": username, "changed": "true"}, response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]

        except botocore.exceptions.ClientError as err:
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.error(e)
            return {
                "message",
                SERVER_ERROR_MESSAGE,
            }, requests.codes.unprocessable_entity

    @staticmethod
    def logout(client_id, logout_uri):
        return redirect(
            "{base_url}/logout?client_id={client_id}&logout_uri={logout_uri}".format(
                base_url=os.getenv("AWS_AUTH_URL", ""),
                client_id=client_id,
                logout_uri=logout_uri,
            ),
            code=302,
        )

    def token_refresh(self, refresh_token=None, client_id=None, auth_header=None):
        domain_name = self.user_pool.get("Domain", None)

        if not domain_name:
            logger.error("Domain name not in user pool description.")
            return {"message": "Missing domain name."}, requests.codes.server_error

        r = requests.post(
            url="https://{domain_name}.auth.eu-west-1.amazoncognito.com/oauth2/token?grant_type=refresh_token&client_id={client_id}&refresh_token={refresh_token}".format(
                domain_name=domain_name,
                client_id=client_id,
                refresh_token=refresh_token,
            ),
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "Authorization": auth_header,
            },
        )

        if r.status_code == requests.codes.ok:
            return r.json(), requests.codes.ok
        else:
            return {"message": "Token refresh failure."}, requests.codes.unauthorized

    def token_refresh_v2(
        self, refresh_token=None, client_id=None, auth_header=None, pool_id=None
    ):

        logger.debug("Auth Header: {}".format(auth_header))
        logger.debug("client_id: {}".format(client_id))

        if not refresh_token:
            return {"message": "Missing refresh token."}, requests.codes.bad_request

        try:
            response = self.cognito_client.admin_initiate_auth(
                UserPoolId=pool_id,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={"REFRESH_TOKEN": refresh_token},
                ClientId=self.user_pool["IdamClientNoSecret"]["ClientId"],
            )

            logger.debug("init_auth response: {}".format(response))

            if response["ResponseMetadata"]["HTTPStatusCode"] != requests.codes.ok:
                return {
                    "message": "Unknown error with token refresh."
                }, requests.codes.unauthorized

            result = response["AuthenticationResult"]

            return {
                "token_type": result.get("TokenType", ""),
                "expiry": result.get("ExpiresIn", ""),
                "access_token": result.get("AccessToken", ""),
                "refresh_token": result.get("RefreshToken", ""),
            }, requests.codes.ok

        except botocore.exceptions.ClientError as err:
            logger.error(f"{err.response['Error']['Message']}")
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.error(e)
            return {"message": SERVER_ERROR_MESSAGE}, requests.codes.server_error

    def list_user_pools(self):
        response = self.cognito_client.list_user_pools(MaxResults=50)
        logger.debug(response)
        return response.get("UserPools", list())

    def update_last_seen(self, username):
        try:
            self.cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool["Id"],
                Username=username,
                UserAttributes=[
                    {
                        "Name": "custom:last_seen",
                        "Value": datetime.utcnow()
                        .replace(tzinfo=simple_utc())
                        .isoformat(),
                    }
                ],
            )
            return True
        except botocore.exceptions.ClientError as err:
            logger.debug(err)
            return False
        except Exception as e:
            logger.debug(e)
            return False

    def user_email_exists(self, email):
        try:
            userlist = self.cognito_client.list_users(
                UserPoolId=self.user_pool["Id"],
                AttributesToGet=[
                    "email",
                ],
                Filter='email = "%s"' % email,
            )
            if "Users" in userlist and len(userlist["Users"]) > 0:
                return True
            else:
                return False

        except Exception:
            return None
