from src.models.eligible_email import EmailModel
from src.models.eligible_domain import DomainModel
from src.models.blocked_emails import BlockedEmailModel
from src.common import app_logger


logger = app_logger.logging.getLogger(__name__)


def email_allowed(email_address=None):
    """Check email allowed and not on block list

    Args:
        email_address (string, optional): email address. Defaults to None.

    Returns:
        boolean: True if allowed, False if not allowed.
    """
    if not email_address:
        return False

    _, domain = email_address.split("@")

    # block list takes precedence
    if BlockedEmailModel.find_by_email(email_address):
        logger.debug("Email is on block list")
        return False
    if EmailModel.find_by_email(email_address):
        logger.debug("Email found.")
        return True
    elif DomainModel.find_by_domain_name(domain):
        logger.debug("Domain found.")
        return True
    else:
        logger.debug("Email/Domain not found.")
        return False
