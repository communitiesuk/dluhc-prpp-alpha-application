import os
import requests
import base64
import hashlib
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from app.src.common import app_logger

logger = app_logger.logging.getLogger(__name__)

salt = os.getenv("JWT_SECRET_KEY", "SECRET_KEY_123").encode()
hash_salt = os.getenv("JWT_SECRET_KEY", "JWT_KEY_123").encode()


kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend(),
)

key = base64.urlsafe_b64encode(kdf.derive(os.getenv("CLIENT_ID", "CLIENT_ID").encode()))

f = Fernet(key)


def idam_encode(string):
    return f.encrypt(string.encode())


def idam_decode(encoded_bytes):
    if isinstance(encoded_bytes, str):
        return f.decrypt(encoded_bytes.encode()).decode("utf-8")

    return f.decrypt(encoded_bytes).decode("utf-8")


def idam_hash(string):
    return hashlib.sha256(hash_salt + string.encode()).hexdigest()


def generate_nonce(length=8):
    """Generate pseudorandom number."""
    return "".join([str(random.randint(0, 9)) for i in range(length)])


def generate_state(length=8):
    """Generate pseudorandom state value."""
    return "".join([str(random.choice(0, 9)) for i in range(length)])


def idam_unhash(string):
    return hashlib.sha256(hash_salt.encode() + string.encode()).hexdigest()


def get_access_token(url, client_id, client_secret):
    response = requests.post(
        url,
        data={"grant_type": "client_credentials"},
        auth=(client_id, client_secret),
    )
    

    return response


def check_env_vars():
    """Checks that environment variables have been set.
    Returns:
        boolean: True if envs have been set, False if not.
    """
    if not os.getenv("JWT_SECRET_KEY"):
        print("JWT_SECRET_KEY ERROR")
        return False
    if not os.getenv("USER_POOL_ID"):
        print("USER_POOL_ID ERROR")
        return False
    if not os.getenv("CLIENT_ID"):
        print("CLIENT_ID ERROR")
        return False
    return True


def get_gov_info():
    pass

def get_aws_info():
    pass