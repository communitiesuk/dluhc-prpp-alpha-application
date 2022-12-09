import botocore
from datetime import datetime
from src.auth.authentication import Authenticator
from src.auth.hash_functions import get_secret_hash
from src.auth.authentication import simple_utc
from src.schemas.user_schema import UserType
from src.common import app_logger
import src.common.error_messages as error_messages

logger = app_logger.logging.getLogger(__name__)


class UserManager(Authenticator):
    def __init__(
        self, client=None, user_pool_id=None, user_pool_name=None, client_id=None
    ):
        super().__init__(
            client=client,
            user_pool_id=user_pool_id,
            user_pool_name=user_pool_name,
            client_id=client_id,
        )

    @staticmethod
    def authorise(tg_mngr=None, access_token=None, admin_only=False):
        try:
            get_user_response, status = tg_mngr.get_user(access_token=access_token)
            if status != 200:
                return {"message": "Unauthorized."}, 401

            if admin_only:
                if UserType.COMPETITION_ADMIN not in get_user_response["user_groups"]:
                    return {"message": "Unauthorized."}, 401
            else:
                if (
                    UserType.GUARDIAN not in get_user_response["user_groups"]
                    and UserType.COMPETITION_ADMIN
                    not in get_user_response["user_groups"]
                ):
                    return {"message": "Unauthorized."}, 401

        except botocore.exceptions.ClientError as err:
            logger.debug(err)
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug(e)
            return {"message": "Error with get_user."}, 500

        return get_user_response, status

    def create_user(
        self, username=None, password=None, access_token=None, tg_mngr=None
    ):
        # do a get_user(access_token) and check if they are TeamGuardian
        message, status = self.authorise(tg_mngr=tg_mngr, access_token=access_token)

        if status != 200:
            return message, status

        try:
            response = self.cognito_client.admin_create_user(
                UserPoolId=self.user_pool["Id"],
                Username=username,
                TemporaryPassword=password,
                MessageAction="SUPPRESS",
                UserAttributes=[{"Name": "preferred_username", "Value": username}],
            )
            logger.debug(response)

            # Add the user to the Competitor group
            try:
                _, status = self.add_user_to_group(
                    username=username, group_name=UserType.COMPETITOR
                )
            except Exception as e:
                logger.debug(e)
                return {"message": error_messages.UNABLE_TO_ADD_USER_MESSAGE}, 400

            if status != 200:
                if status == 400:
                    # try and create the group
                    try:
                        self.cognito_client.create_group(
                            GroupName=UserType.COMPETITOR,
                            UserPoolId=self.user_pool["Id"],
                        )
                    except self.cognito_client.exceptions.GroupExistsException as err:
                        logger.debug(err)
                    except botocore.exceptions.ClientError as err:
                        return {
                            "message": f"{err.response['Error']['Message']}"
                        }, err.response["ResponseMetadata"]["HTTPStatusCode"]

                    # Now that we have created the group because it didn't exist, try and add the user again.
                    try:
                        _, status = self.add_user_to_group(
                            username=username, group_name=UserType.COMPETITOR
                        )
                    except Exception as e:
                        logger.debug(e)
                        return {
                            "message": error_messages.UNABLE_TO_ADD_USER_MESSAGE
                        }, 400
                else:
                    return {"message": "Could not add user to group."}, 400

            return {
                "message": "User created.",
                "username": response["User"]["Username"],
            }, 201
        except self.cognito_client.exceptions.UsernameExistsException as err:
            logger.debug(err)
            return {"message": "Username already exists.", "username": username}, 400
        except botocore.exceptions.ClientError as err:
            logger.debug(err)
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug(e)
            return {"message": "Create user unknown error."}, 422

    def reset_password(
        self,
        username=None,
        password=None,
        permanent=True,
        access_token=None,
        tg_mngr=None,
    ):
        message, status = self.authorise(tg_mngr=tg_mngr, access_token=access_token)

        if status != 200:
            return message, status

        try:
            response = self.cognito_client.admin_set_user_password(
                UserPoolId=self.user_pool["Id"],
                Username=username,
                Password=password,
                Permanent=permanent,
            )
            logger.debug(response)
            return {
                "message": "User password reset.",
            }, 200
        except botocore.exceptions.ClientError as err:
            logger.debug(err)
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug(e)
            return {"message": "Password reset unknown error."}, 422

    def delete_user(
        self,
        username=None,
        access_token=None,
        tg_mngr=None,
        u18_user_pool_id=None,
    ):
        message, status = self.authorise(tg_mngr=tg_mngr, access_token=access_token)

        u18_check = None
        o18_check = None

        if status != 200:
            return message, status

        try:
            self.cognito_client.admin_get_user(
                UserPoolId=u18_user_pool_id, Username=username
            )
            self.cognito_client.admin_delete_user(
                UserPoolId=u18_user_pool_id, Username=username
            )
            return {"message": "User deleted."}, 200
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] == "UserNotFoundException":
                u18_check = "UserNotFoundException"
            logger.debug(err)
        except Exception as e:
            logger.debug(f"Error deleting under18 user: {e}")

        try:
            self.cognito_client.admin_get_user(
                UserPoolId=self.user_pool["Id"], Username=username
            )
            self.cognito_client.admin_delete_user(
                UserPoolId=self.user_pool["Id"],
                Username=username,
            )
            return {"message": "User deleted."}, 200
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] == "UserNotFoundException":
                o18_check = "UserNotFoundException"
            logger.debug(err)
        except Exception as e:
            logger.debug(f"Error deleting over18 user: {e}")

        if o18_check and u18_check == "UserNotFoundException":
            logger.debug("Deleting user as not found in user pools")
            return {"message": "User deleted."}, 200
        else:
            return {"message": "Delete user unknown error."}, 422

    def edit_user(
        self,
        old_username=None,
        new_username=None,
        access_token=None,
        tg_mngr=None,
    ):
        message, status = self.authorise(tg_mngr=tg_mngr, access_token=access_token)

        if status != 200:
            return message, status

        try:
            self.cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool["Id"],
                Username=old_username,
                UserAttributes=[{"Name": "preferred_username", "Value": new_username}],
            )
            return {
                "message": "User updated.",
            }, 200
        except botocore.exceptions.ClientError as err:
            logger.debug(err)
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug(e)
            return {"message": "Edit user unknown error."}, 422

    def return_users(self, access_token=None, user_mngr=None):
        # do a get_user(access_token) and check if they are an admin
        message, status = self.authorise(
            tg_mngr=user_mngr, access_token=access_token, admin_only=True
        )

        if status != 200:
            return message, status

        try:
            poolusers = []

            list_users_args = {
                "UserPoolId": self.user_pool["Id"],
                "Limit": 60,
            }

            response = self.cognito_client.list_users(**list_users_args)
            poolusers += response["Users"]

            while "PaginationToken" in response:
                response = self.cognito_client.list_users(
                    **list_users_args, PaginationToken=response["PaginationToken"]
                )
                poolusers += response["Users"]

            for u in poolusers:
                u["UserLastModifiedDate"] = u["UserLastModifiedDate"].isoformat()
                u["UserCreateDate"] = u["UserCreateDate"].isoformat()

                if "Attributes" in u:
                    for a in u["Attributes"]:
                        if a["Name"] not in u:
                            nme = a["Name"]
                            try:
                                if str(nme).startswith("custom:"):
                                    nme = nme[7:]
                            except Exception:  # nosec
                                pass  # nosec

                            u[nme] = a["Value"]

                    del u["Attributes"]

                    # last_seen is a new custom attrib (added after the original set).
                    # Existing users won't have this key until it is set,
                    # but I want it in the response regardless.
                    if "last_seen" not in u:
                        u["last_seen"] = ""

                    # mfa_setup_complete is a new custom attrib (added after the original set).
                    # Existing users won't have this key until it is set,
                    # but I want it in the response regardless.
                    if "mfa_setup_complete" not in u:
                        u["mfa_setup_complete"] = ""

                    # mfa_setup_complete is a new custom attrib (added after the original set).
                    # Existing users won't have this key until it is set,
                    # but I want it in the response regardless.
                    if "verified_at" not in u:
                        u["verified_at"] = ""

                    if "email_verified" not in u:
                        if "UserStatus" in u and u["UserStatus"] == "CONFIRMED":
                            u["email_verified"] = "true"
                        else:
                            u["email_verified"] = "false"

                    u["registration_status"] = "Awaiting email verification"

                    if u["email_verified"] == "true":
                        u["registration_status"] = "Awaiting 2FA setup"

                    if u["mfa_setup_complete"] == "1" and u["email_verified"] == "true":
                        u["registration_status"] = "Complete"

                    if u["mfa_setup_complete"] == "1" and u["email_verified"] != "true":
                        u["registration_status"] = "Email unverified. 2FA complete."

            return poolusers
        except botocore.exceptions.ClientError as err:
            logger.debug(err)
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug(e)
            return {"message": "List users unknown error."}, 422

    def resend_email_verification(
        self,
        username=None,
        access_token=None,
        tg_mngr=None,
    ):
        message, status = self.authorise(tg_mngr=tg_mngr, access_token=access_token)

        if status != 200:
            return message, status

        try:

            response = self.cognito_client.resend_confirmation_code(
                ClientId=self.user_pool["IdamClient"]["ClientId"],
                SecretHash=get_secret_hash(
                    username,
                    client_id=self.user_pool["IdamClient"]["ClientId"],
                    client_secret=self.user_pool["IdamClient"]["ClientSecret"],
                ),
                Username=username,
            )
            logger.debug(response)
            return {
                "message": "Email sent",
            }, 200
        except botocore.exceptions.ClientError as err:
            logger.debug(err)
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug(e)
            return {"message": "Resend email verification unknown error."}, 422

    def force_verification(
        self,
        username=None,
        access_token=None,
        tg_mngr=None,
    ):
        message, status = self.authorise(tg_mngr=tg_mngr, access_token=access_token)

        if status != 200:
            return message, status

        try:
            self.cognito_client.admin_confirm_sign_up(
                UserPoolId=tg_mngr.user_pool["Id"],
                Username=username,
            )
            self.cognito_client.admin_update_user_attributes(
                UserPoolId=tg_mngr.user_pool["Id"],
                Username=username,
                UserAttributes=[
                    {"Name": "email_verified", "Value": "true"},
                    {
                        "Name": "custom:verified_at",
                        "Value": datetime.utcnow()
                        .replace(tzinfo=simple_utc())
                        .isoformat(),
                    },
                ],
            )
            return {
                "message": "User updated.",
            }, 200
        except botocore.exceptions.ClientError as err:
            logger.debug(err)
            return {"message": f"{err.response['Error']['Message']}"}, err.response[
                "ResponseMetadata"
            ]["HTTPStatusCode"]
        except Exception as e:
            logger.debug(e)
            return {"message": "Edit user unknown error."}, 422
