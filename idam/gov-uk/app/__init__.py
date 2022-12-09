import os
from flask import Flask
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow


from flask_compress import Compress
from flask_talisman import Talisman
from jinja2 import ChoiceLoader, PackageLoader, PrefixLoader


app = Flask(__name__, static_url_path="/assets")

app.secret_key = "#y2LF4Q8zxec"

app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "SECRET_KEY_123")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI", "")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
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
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["SESSION_PERMANENT"] = True

Session(app)

ma = Marshmallow()
db = SQLAlchemy()

ma.init_app(app)
db.init_app(app)


app.jinja_loader = ChoiceLoader(
    [
        PackageLoader("app"),
        PrefixLoader({"govuk_frontend_jinja": PackageLoader("govuk_frontend_jinja")}),
    ]
)

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

csp = {
    "default-src": "'self'",
    "script-src": [
        "'self'",
        "'sha256-+6WnXIl4mbFTCARd8N3COQmT3bJJmo32N8q8ZSQAIcU='",
        "'sha256-l1eTVSK8DTnK8+yloud7wZUqFrI0atVo6VlC6PJvYaQ='",
    ],
}

Compress(app)
Talisman(app, content_security_policy=csp)

from app import routes  # noqa: E402, F401
