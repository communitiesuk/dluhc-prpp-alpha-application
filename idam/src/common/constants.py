import os
import json


class PendingStatus:
    PENDING = "pending"
    AWAITING_RESPONSE = "awaiting_response"
    TELEPHONED = "telephoned"
    EMAILED = "emailed"

    VALID_OPTIONS = (PENDING, AWAITING_RESPONSE, TELEPHONED, EMAILED)


PERF_TEST = json.loads(os.getenv("PERF_TEST", "False").lower())


class ThemeType:
    AUTHORING = 1
    COMPETITION = 2
    LEARNING = 3

    VALID_OPTIONS = (AUTHORING, COMPETITION, LEARNING)


class ClientNames:
    IDAM_CLIENT_NAME = "IDAM-BACKEND"
    IDAM_NO_SEC_CLIENT_NAME = "IDAM-BACKEND-NO-SECRET"
    PLATFORM_CLIENT_NAME = "COMPETITION-PLATFORM"
