import os
import logging
from uuid import uuid1

logger = logging.getLogger(__name__)

GOOD_REDIRECT_URI = "http://authoring.co.uk/redirect"
GOOD_REDIRECT_URI2 = "http://authoring1.co.uk/redirect"
BAD_REDIRECT_URI = "http://not.authoring.co.uk/redirect"

API_KEY = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1dWlkIjoiY2QyYzFmZDItZDAxYi00ZWFkLWI4NGYtZDA2YjU3ZDQ3YjQ4IiwiYWNjZXNzX3R5cGUiOiJSVyJ9.vFhCtBXL7hjgcnZW1r9GSHNmbS08VCwSSHdXw11M5EQ"

DEFAULT_POOL_NAME = "cf-challenge-authoring-test"
DEFAULT_COMP_POOL_NAME = "cf-competition-comp-a-test"
DEFAULT_COMP_U18_POOL_NAME = "cf-competition-tg-comp-a-test"

POOLS_ENDPOINT = "/api/pools"

cognito_pools = [
    {
        "name": DEFAULT_POOL_NAME,
        "type": "author",
    },
    {
        "name": DEFAULT_COMP_POOL_NAME,
        "type": "comp",
    },
    {
        "name": "cf-competition-comp-b-test",
        "type": "comp",
    },
    {
        "name": DEFAULT_COMP_U18_POOL_NAME,
        "type": "u18_comp",
    },
]


def generate_random_email():
    """Returns a random AWS email for testing purposes."""
    return "success+{}@simulator.amazonses.com".format(uuid1())

