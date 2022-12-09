import os
from src.common.utils import check_env_vars
import logging

LOGGER = logging.getLogger(__name__)


def test_check_env_vars_success():
    """Test that the environment util
    function returns correctly.
    """
    os.environ["JWT_SECRET_KEY"] = "set"
    os.environ["USER_POOL_ID"] = "set"
    os.environ["CLIENT_ID"] = "set"

    assert check_env_vars() is True

    os.environ.pop("CLIENT_ID")
    assert check_env_vars() is False

    os.environ.pop("USER_POOL_ID")
    assert check_env_vars() is False

    os.environ.pop("JWT_SECRET_KEY")
    assert check_env_vars() is False
