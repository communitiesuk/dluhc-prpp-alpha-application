import hmac
import hashlib
import base64


def get_secret_hash(username, client_id=None, client_secret=None):
    """Generates a keyed-hash message authentication code (HMAC) calculated
    using the secret key of a user pool client and username plus the client ID
    in the message.

    Args:
        username (str): Username for the new user.

    Returns:
        str: Secret Hash string
    """
    msg = username + client_id
    dig = hmac.new(
        str(client_secret).encode("utf-8"),
        msg=str(msg).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()

    return base64.b64encode(dig).decode()
