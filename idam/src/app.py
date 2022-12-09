import json
import os
from datetime import datetime

import redis


from flask import Flask, jsonify, make_response
from flask_cors import CORS
from flask_restful import Api
from flask_session import Session

from src.common import app_logger
from src.common.utils import check_env_vars
from src.db import db
from src.ma import ma
from src.resources.eligibility_domain import EligibilityDomainResource
from src.resources.eligibility_email import EligibilityEmailResource
from src.resources.gov_uk import (
    GovUKAuthorizeResource,
    GovUKRedirectResource,
    GovUKDiscoveryResource,
    GovUKLoginResource,
    GovUKLogoutResource,
    GovUKRegisterResource,
    GovUKTokenResource,
    GovUKUserInfoResource,
    GovUKSignoutResource
)
from src.resources.org_db import OrgResource
from src.resources.user import (
    ChangePassword,
    ConfirmTOTP,
    ForgotPassword,
    ResetPassword,
    UserLogin,
    UserRegister,
    Verify,
    VerifyTOTP,
)
from src.security.security import api_key_all

logger = app_logger.logging.getLogger(__name__)

app = Flask(__name__)

app.config["JSON_SORT_KEYS"] = json.loads(
    os.environ.get("JSON_SORT_KEYS", "False").lower()
)

app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI", "")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REMEMBER_COOKIE_DOMAIN"] = os.environ.get(
    "COOKIE_DOMAINS",
    [
        "localhost:3000",
        "cyberfirst.ncscdev.co.uk",
        ".old.cyberfirst.ncsc.gov.uk",
        ".cyberfirst.ncsc.gov.uk",
    ],
)
app.config["PERMANENT_SESSION_LIFETIME"] = int(
    os.environ.get("IDAM_SESSION_LIFETIME", 604800)
)  # default: 1 day
DATABASE_POOL_SIZE = int(os.getenv("DATABASE_POOL_SIZE") or 340)
DATABASE_POOL_RECYCLE = int(os.getenv("DATABASE_POOL_RECYCLE") or 3600)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": DATABASE_POOL_SIZE,
    "pool_recycle": DATABASE_POOL_RECYCLE,
    "pool_pre_ping": True,
    "max_overflow": int(os.getenv("SQLALCHEMY_MAX_OVERFLOW", 20)),
}

app.config.update(
    SESSION_COOKIE_NAME=os.environ.get("SESSION_COOKIE_NAME", "idam_session")
)

db.init_app(app)
ma.init_app(app)

app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY")
app.config['SESSION_PERMANENT'] = True


# if os.environ.get("REDIS_URL"):
#     logger.debug("Production redis...")
#     app.config["SESSION_TYPE"] = "redis"
#     app.config["SESSION_REDIS"] = redis.from_url(os.environ.get("REDIS_URL"))

# else:
#     logger.debug("Test sqlalchemy...")
#     app.config["SESSION_TYPE"] = "sqlalchemy"
#     app.config["SESSION_SQLALCHEMY_TABLE"] = "idam_sessions"
#     app.config["SESSION_SQLALCHEMY"] = db

secure_cookie = json.loads(os.environ.get("SESSION_COOKIE_SECURE", "False").lower())
logger.critical(f"SESSION_COOKIE_SECURE: {secure_cookie}")
app.config["SESSION_COOKIE_SECURE"] = secure_cookie
app.config["SESSION_USE_SIGNER"] = True
sess = Session()
sess.init_app(app)

api = Api(app)

CORS(app, supports_credentials=True)


# @app.before_first_request
# def create_tables():
#     db.create_all()


NO_ID_ERROR_MSG = "No version defined!"
NO_LEVEL = "No logging level set."


@app.route("/api/ping", methods=["GET"])
def ping():
    """An API endpoint that is a sanity check that the API
    is reachable.  Primarily used for debugging.  It also checks that
    the envirnoment variables have been set, see [envVarsTest].

    Returns:
        tuple: a JSON object and HTTP status code.
    """
    response = make_response(
        jsonify(
            {
                "message": "Hello world, from IDAM version {}".format(
                    os.environ.get("APP_VERSION", NO_ID_ERROR_MSG)
                ),
                "env_vars_test": check_env_vars(),
                "local_time": datetime.now(),
            }
        )
    )
    return response


@app.route("/api/info", methods=["GET"])
@api_key_all
def info():
    """As per Openapi 3.0.3 specification this function returns the
    minimum required information.

    Returns:
        tuple: a JSON object containing the Openapi info block and
        HTTP status code.
    """
    return (
        jsonify(
            {
                "openapi": os.environ.get("OPENAPI_VERSION", NO_ID_ERROR_MSG),
                "info": {
                    "title": os.environ.get("TITLE", ""),
                    "version": os.environ.get("APP_VERSION", NO_ID_ERROR_MSG),
                },
                "paths": ["%s" % rule for rule in app.url_map.iter_rules()],
                "log_level": os.environ.get("LOG_LEVEL", NO_LEVEL),
            }
        ),
        200,
    )


api.add_resource(GovUKAuthorizeResource, "/login")
api.add_resource(GovUKRedirectResource, "/redirect")
api.add_resource(GovUKDiscoveryResource, "/discovery")
# api.add_resource(GovUKLoginResource, "/login")
api.add_resource(GovUKLogoutResource, "/logout")
api.add_resource(GovUKRegisterResource, "/register")
api.add_resource(GovUKTokenResource, "/token")
api.add_resource(GovUKUserInfoResource, "/user-info")
api.add_resource(GovUKSignoutResource, "/signout")

api.add_resource(UserRegister, "/api/register")

api.add_resource(UserLogin, "/api/login")
api.add_resource(VerifyTOTP, "/api/verify-totp")
api.add_resource(ConfirmTOTP, "/api/totp")
api.add_resource(Verify, "/api/verify")

api.add_resource(ForgotPassword, "/api/forgot-password")
api.add_resource(ResetPassword, "/api/password-reset")
api.add_resource(ChangePassword, "/api/password-change")


api.add_resource(
    EligibilityDomainResource,
    "/api/domain",
    "/api/domain/<string:domain_name>",
    "/api/domain/<int:domain_id>",
    endpoint="domain",
)
api.add_resource(
    EligibilityEmailResource,
    "/api/email",
    "/api/email/<string:email_address>",
    "/api/email/<int:email_id>",
    endpoint="email",
)
api.add_resource(
    OrgResource,
    "/api/orgs",
    "/api/orgs/<int:record_id>",
    endpoint="orgs",
)
