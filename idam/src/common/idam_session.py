from src.common import app_logger
from flask import session

logger = app_logger.logging.getLogger(__name__)


def idam_logout():
    try:
        session.clear()
    except Exception as e:
        logger.error(e)
