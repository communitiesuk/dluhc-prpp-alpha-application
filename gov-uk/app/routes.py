import json
import os
import time
import jwt
import requests
import random
import uuid

from app.src.common.utils import idam_decode, idam_encode


from cryptography.hazmat.primitives import serialization


from flask import (
    Flask,
    jsonify,
    make_response,
    render_template,
    redirect,
    session,
    request,
)
from flask_session import Session

from app.src.common import app_logger
from app.src.common import utils

from app.src.schemas.user_schema import (
    # AgentSchema,
    # LandlordSchema,
    # LoginSchema,
    User,
    UserSchema,
    UserType,
    # ChangeUsernameSchema,
    # ChangePasswordSchema,
)

from app.src.auth.authentication import Authenticator


from werkzeug.exceptions import NotFound

from app import app

app.secret_key = os.environ.get("APP_SECRET_KEY", "#y2LF4Q8zxec")

app.config["PERMANENT_SESSION_LIFETIME"] = int(
    os.environ.get("IDAM_SESSION_LIFETIME", 604800)
)  # default: 1 day

app.config.update(
    SESSION_COOKIE_NAME=os.environ.get("SESSION_COOKIE_NAME", "idam_session")
)

app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.secret_key = os.getenv("JWT_SECRET_KEY")
app.config["SESSION_PERMANENT"] = True

NO_ID_ERROR_MSG = "No version defined!"
NO_LEVEL = "No logging level set."

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


GOV_UK_CLIENT_ID = os.getenv("GOV_UK_CLIENT_ID")
GOV_UK_REDIRECT_URL = "https://prpp-alpha.labs.zaizicloud.net/redirect"
COGNITO_REDIRECT_URL = (
    "https://prpp-oidc.auth.eu-west-2.amazoncognito.com/oauth2/idpresponse"
)
GOV_UK_APP = "https://app.prpp-alpha.labs.zaizicloud.net/"

GOV_UK_UI_LOCALES = "en"


UNAUTHORIZED_CLIENT_ID_ERROR_MSG = "Unauthorized client id."
NO_DATA_PROVIDED_ERROR_MESSAGE = "No input data provided."

private_key = os.environ.get("PRIVATE_KEY")


@app.route("/")
def index():
    components = os.listdir("govuk_components")
    components.sort()
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound
    if session.get("id"):
        return dashboard()

    return render_template("index.html", components=components)


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
                # "env_vars_test": check_env_vars(),
                # "local_time": datetime.now(),
            }
        )
    )
    return response


@app.route("/api/info", methods=["GET"])
def info():
    """As per Openapi 3.0.3 specification this function returns the
    minimum required information.

    Returns:
        tuple: a JSON object containing the Openapi info block and
        HTTP status code.
    """

    env_vars = os.environ.keys()
    for var in env_vars:
        print(f"{var}: {os.environ[var]}")

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


@app.route("/home")
def home():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    return render_template("home.html", fixtures=fixtures)


# make the token request, save tokens, send user to dashboard when logged in
@app.route("/redirect")
def gov_redirect():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    print("request")
    print(request)
    print(request.args.get("code"))

    if not request.args:
        return {"message": "NO DATA"}, 400

    try:
        session["authorization_code"] = request.args.get("code")

        # payload = {
        #     "aud": "https://oidc.integration.account.gov.uk/token",
        #     "iss": GOV_UK_CLIENT_ID,
        #     "sub": GOV_UK_CLIENT_ID,
        #     "exp": int(time.time() + 300),
        #     "jti": utils.generate_nonce(),
        #     "iat": int(time.time()),
        # }

        token = jwt.encode(
            {
                "aud": "https://oidc.integration.account.gov.uk/token",
                "iss": GOV_UK_CLIENT_ID,
                "sub": GOV_UK_CLIENT_ID,
                "exp": int(time.time() + 300),
                "jti": utils.generate_nonce(),
                "iat": int(time.time()),
            },
            key=private_key,
            algorithm="RS256",
        )

        print("TOKEN", token)

        host = GOV_UK_TOKEN_URL
        grant_type = "authorization_code"
        redirect_uri = PRPP_REDIRECT_URL
        client_assertion = token
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        code = session["authorization_code"]

        payload = {
            "grant_type": grant_type,
            "redirect_uri": redirect_uri,
            "code": code,
            "client_assertion": client_assertion,
            "client_assertion_type": client_assertion_type,
        }

        print(payload)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            response = requests.request("POST", url=host, headers=headers, data=payload)
        except Exception as e:
            print(f"Exception here, {e}")

        print("RESPONSE", response.text)

        access_token = response.json().get("access_token")
        id_token = response.json().get("id_token")
        token_type = response.json().get("token_type")
        expires_in = response.json().get("expires_in")

        session["access_token"] = access_token
        session["id_token"] = id_token
        session["token_type"] = token_type
        session["expires_in"] = expires_in
        session["expires_at"] = time.time() + expires_in
        session["account"] = "gov"

        print(session["access_token"])

        print({"message": "Received Token"})

        # redirect to dashboard
        # call user info endpoint

        # validate token
        return dashboard()

    except Exception as e:
        return {"message": f"Error: {e}"}, 403

    return render_template("redirect.html")


@app.route("/gov-login")
def gov_login():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    print("Gov login")
    try:
        host = GOV_UK_AUTHORIZE_URL
        response_type = "code"
        scope = "openid"
        client_id = GOV_UK_CLIENT_ID
        state = "STATE"
        redirect_uri = GOV_UK_REDIRECT_URL
        nonce = utils.generate_nonce()
        ui_locales = GOV_UK_UI_LOCALES

        return redirect(
            f"{host}?response_type={response_type}&client_id={client_id}&scope={scope}&state={state}&redirect_uri={redirect_uri}&nonce={nonce}&ui_locales={ui_locales}",
        )
    except Exception as e:
        print("Error authorizing", e)

    return render_template("login.html", fixtures=fixtures)


@app.route("/view-epc", methods=["GET", "POST"])
def view_epc():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    print("EPC View")
    try:
        # send get request to retrieve epc assessment
        epc_id = session["epc_assessment"]
        url = f"https://api.epb-staging.digital.communities.gov.uk/api/heat-pump-check/assessments/{epc_id}"
        headers = {
            "Authorization": "Bearer " + session.get("token"),
        }
        payload = {}
        response = requests.request("GET", url, headers=headers, data=payload)
        print(response.json())
        epc_data = response.json().get("data")
    except Exception as e:
        print("Error retrieving epc", e)

    
    return render_template("view-epc.html", fixtures=fixtures, epc_data=epc_data)



# TBD
@app.route("/cognito-login", methods=["GET", "POST"])
def cognito_login():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    if request.method == "POST":
        print(request)

        username = request.form["username"]
        password = request.form["password"]
        account_type = request.form["account_type"]

        if account_type == "local":
            client_id = os.getenv("LOCAL_AUTHORITY_CLIENT_ID")
            userpool_id = os.getenv("LOCAL_USERPOOL_ID")

        else:
            client_id = os.getenv("AGENT_CLIENT_ID")
            userpool_id = os.getenv("AGENT_USERPOOL_ID")

        print(client_id, userpool_id)
        try:
            auth = Authenticator(user_pool_id=userpool_id, client_id=client_id)
        except Exception as e:
            print("Exception here", e)

        response = auth.login(
            username=username, password=password, account_type=account_type
        )

        print("Response", response)

        aws_response = response[0]
        session["id"] = str(uuid.uuid4())
        session["access_token"] = idam_encode(
            aws_response["AuthenticationResult"]["AccessToken"]
        )
        session["refresh_token"] = idam_encode(
            aws_response["AuthenticationResult"]["RefreshToken"]
        )
        session["expiry"] = aws_response["AuthenticationResult"]["ExpiresIn"]
        session["timestamp"] = time.time()
        session["pool_id"] = userpool_id
        session["client_id"] = client_id

        print("ID", session["id"])

        if response[1] == 200:
            return render_template("login-success.html", fixtures=fixtures)
        else:
            return render_template("login-fail.html", fixtures=fixtures)

    return render_template("login.html", fixtures=fixtures)


@app.route("/logout")
def logout():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    for key in list(session.keys()):
        session.pop(key)

    return render_template("logout.html", fixtures=fixtures)


@app.route("/gov-logout")
def gov_logout():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound
    try:
        host = GOV_UK_LOGOUT_URL
        id_token_hint = session["id_token"]
        post_logout_redirect_uri = PRPP_LOGOUT_URL
        state = utils.generate_nonce()

        return redirect(
            f"{host}?id_token_hint={id_token_hint}&post_logout_redirect_uri={post_logout_redirect_uri}&state={state}",
            code=302,
        )
    except Exception as e:
        print("Logout Error", e)

    return render_template("logout.html", fixtures=fixtures)


@app.route("/cognito-register", methods=["GET", "POST"])
def cognito_register():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    if request.method == "POST":
        print(request)

        username = request.form["username"]
        password = request.form["password"]
        account_type = request.form["account_type"]

        if account_type == "local":
            client_id = os.getenv("LOCAL_AUTHORITY_CLIENT_ID")
            userpool_id = os.getenv("LOCAL_USERPOOL_ID")
            pool_name = "dluhc-prpp-alpha-5472-la-employees"

        else:
            client_id = os.getenv("AGENT_CLIENT_ID") 
            userpool_id = os.getenv("AGENT_ID")
            pool_name = "dluhc-prpp-alpha-5472-agents"

        auth = Authenticator(client_id=client_id, user_pool_id=userpool_id)

        json_data = {}

        json_data["user_type"] = UserType.USER
        json_data["account_type"] = account_type
        json_data["username"] = username
        json_data["password"] = password

        try:
            json_data["user_type"] = account_type
            json_data.pop("account_type")
            json_data["pool_name"] = pool_name
            json_data["email"] = username
        except Exception as e:
            print("Exception here", e)

        try:
            user = UserSchema()
            data = user.load(data=json_data)
            user_model = User(data=data)
        except Exception as e:
            print("Exception here 2", e)

        response = auth.sign_up(user_model)

        print((response[0], response[1]))

        if response[1] == 200:
            return render_template("register-success.html", fixtures=fixtures)
        else:
            return render_template("register-fail.html", fixtures=fixtures)

    return render_template("register.html", fixtures=fixtures)


@app.route("/token")
def token():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    payload = {
        "aud": "https://oidc.integration.account.gov.uk/token",
        "iss": GOV_UK_CLIENT_ID,
        "sub": GOV_UK_CLIENT_ID,
        "exp": utils.generate_nonce(),
        "jti": int(time.time() + 300),
        "iat": int(time.time()),
    }

    token = jwt.encode(
        {
            "aud": "https://oidc.integration.account.gov.uk/token",
            "iss": GOV_UK_CLIENT_ID,
            "sub": GOV_UK_CLIENT_ID,
            "exp": int(time.time() + 300),
            "jti": utils.generate_nonce(),
            "iat": int(time.time()),
        },
        key=private_key,
        algorithm="RS256",
    )

    print("TOKEN", token)

    try:
        host = GOV_UK_TOKEN_URL
        grant_type = "authorization_code"
        redirect_uri = session["redirect_uri"]
        client_assertion = token
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        code = session["authorization_code"]

        # TBD
        return redirect(
            f"{host}?response_type={response_type}&client_id={client_id}&scope={scope}&state={state}&redirect_uri={redirect_uri}&nonce={nonce}&ui_locales={ui_locales}",
            code=302,
        )
    except Exception as e:
        print("Error authorizing", e)

    return render_template("register.html", fixtures=fixtures)


@app.route("/reset-password")
def reset_password():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound
    return render_template("reset-password.html", fixtures=fixtures)



@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    if request.method == "GET":
        if session.get("id"):
            # get aws user info
            aws_info = utils.get_aws_info()
            return render_template(
                "dashboard.html", fixtures=fixtures, aws_info=aws_info
            )
        if session.get("account"):
            # get user info from token
            gov_info = utils.get_gov_info()
            return render_template(
                "dashboard.html", fixtures=fixtures, gov_info=gov_info
            )

    if request.method == "POST":
        address = request.form.get("address")
        postcode = request.form.get("postcode")

        address = f"{address} {postcode}"

        # os places
        api_key = os.getenv("OS_PLACES_API_KEY")
        host = "https://api.os.uk/search/places/v1/find"

        url = f"{host}?key={api_key}&query={address}"

        payload = {}
        headers = {}

        response = requests.request("GET", url, headers=headers, data=payload)

        results = response.json().get("results")
        session["results"] = results
        session["preview_results"] = results[:3]
        preview_results = session["preview_results"]
        

        # epc lookup
        # api_key =

        return render_template("what_is_your_address.html", fixtures=fixtures, results=results, preview_results=preview_results)

    return index()


@app.route("/dashboard-continue", methods=["GET", "POST"])
def select_address():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    if request.method == "GET":
        if session.get("id"):
            # get aws user info
            aws_info = utils.get_aws_info()
            return render_template(
                "dashboard.html", fixtures=fixtures, aws_info=aws_info
            )
        if session.get("account"):
            # get user info from token
            gov_info = utils.get_gov_info()
            return render_template(
                "dashboard.html", fixtures=fixtures, gov_info=gov_info
            )

    if request.method == "POST":
        print(request)
        address = request.form["address"]
        postcode = request.form["postcode"]

        address = f"{address} {postcode}"

        # os places
        api_key = os.getenv("OS_PLACES_API_KEY")
        host = "https://api.os.uk/search/places/v1/find"

        url = f"{host}?key={api_key}&query={address}"

        payload = {}
        headers = {}

        response = requests.request("GET", url, headers=headers, data=payload)

        results = response.json().get("results")
        session["results"] = results

        # epc lookup
        # api_key =

        return render_template("what_is_your_address.html", fixtures=fixtures, results=results)

    return index()


@app.route("/address-select", methods=["GET", "POST"])
def address_select():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError as e:
        print(e)
        raise NotFound

    if request.method == "POST":
        print("FORM")
        print(request.form.get("address-selected"))
        address = request.form.get("address-selected")
        for result in session["results"]:
            if result["DPA"]["UPRN"] == address:
                found_address = result
                session["selected_address"] = result
                print(session["selected_address"])

        # get token for uprn search
        client_id = "3bf2af5f-eb56-4c0c-8f07-25b3d090995e"
        client_secret = (
            "YgYcaERYU5vOJ5FAwoePjF8Vr0ODfTHDAWRNEzArnEZso3SDaMa8wRDoXNfBLW36"
        )
        url = "https://api.epb-staging.digital.communities.gov.uk/auth/oauth/token"

        print(session)
        if time.time() > session.get("token_expires_at", 0):
            token_response = utils.get_access_token(url, client_id, client_secret)
            token = token_response.json()["access_token"]
            token_expires_at = int(token_response.json()["expires_in"]) + int(
                time.time()
            )
            session["token_expires_at"] = token_expires_at
            session["token"] = token
            print(session["token_expires_at"])
            print(token)
        
        token = session["token"]
        # search by UPRN for existing assessment
        EPC_BASE_URL = "https://api.epb-staging.digital.communities.gov.uk"
        search_uprn = session["selected_address"]["DPA"]["UPRN"]
        uprn_search_url = (
            f"{EPC_BASE_URL}/api/search/addresses?addressId=UPRN-{search_uprn}"
        )
        headers = {
            "Authorization": "Bearer " + session.get("token", token),
        }
        payload = {}

        epc = False

        try:
            response = requests.request(
                "GET", url=uprn_search_url, headers=headers, data=payload
            )

            if (
                response.json()
                .get("data")
                .get("addresses")[0]
                .get("existingAssessments")[0]
                .get("assessmentStatus")
                == "ENTERED"
            ):
                print(
                    response.json()["data"]["addresses"][0]["existingAssessments"][0][
                        "assessmentId"
                    ]
                )
                epc = response.json()["data"]["addresses"][0]["existingAssessments"][0][
                    "assessmentId"
                ]

        except Exception as e:
            print("Exception EPC: ", e)
            print("Exception getting EPC data")

        return render_template(
            "selected-address.html", fixtures=fixtures, address=found_address, epc=epc
        )

    return render_template("selected-address.html", fixtures=fixtures, address=address)


@app.route("/compliance")
def compliance():
    component = "header"
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError:
        raise NotFound

    return render_template("compliance.html", fixtures=fixtures)


@app.route("/compliance-home")
def compliance_home():
    component = "header"
    complete = 0
    total = 4
    session["compliance_complete"] = complete
    session["total"] = total
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError:
        raise NotFound

    return render_template(
        "compliance-home.html", fixtures=fixtures, complete=complete, total=total
    )


@app.route("/components/<string:component>")
def component(component):
    try:
        with open("govuk_components/{}/fixtures.json".format(component)) as json_file:
            fixtures = json.load(json_file)
    except FileNotFoundError:
        raise NotFound

    return render_template("component.html", fixtures=fixtures)


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server(error):
    return render_template("500.html"), 500
