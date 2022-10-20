from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route("/login")
def login():
    return "<p>Login</p>"


@app.route("/logout")
def login():
    return "<p>Logout</p>"


@app.route("/register")
def login():
    return "<p>Register</p>"
