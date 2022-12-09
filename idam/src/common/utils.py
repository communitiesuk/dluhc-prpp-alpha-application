import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from src.common import app_logger

logger = app_logger.logging.getLogger(__name__)

salt = os.getenv("JWT_SECRET_KEY").encode()
hash_salt = os.getenv("JWT_SECRET_KEY").encode()


kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend(),
)

key = base64.urlsafe_b64encode(kdf.derive(os.getenv("CLIENT_ID").encode()))

f = Fernet(key)


def idam_encode(string):
    return f.encrypt(string.encode())


def idam_decode(encoded_bytes):
    if isinstance(encoded_bytes, str):
        return f.decrypt(encoded_bytes.encode()).decode("utf-8")

    return f.decrypt(encoded_bytes).decode("utf-8")


def idam_hash(string):
    return hashlib.sha256(hash_salt + string.encode()).hexdigest()


def idam_unhash(string):
    return hashlib.sha256(hash_salt.encode() + string.encode()).hexdigest()


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
