import os
import logging

log_level = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(format="%(levelname)s:%(name)s:%(message)s", level=log_level)
