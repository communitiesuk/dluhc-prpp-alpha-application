from marshmallow import fields, ValidationError
from src.common.utils import idam_encode, idam_decode, idam_hash
from app.src.common import app_logger

logger = app_logger.logging.getLogger(__name__)


class EncryptedField(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        if value is None:
            return ""
        try:
            return idam_decode(value)
        except Exception as e:
            logger.error(f"{e}")
            raise ValidationError("Error decoding string.")

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return idam_encode(value)
        except ValueError as error:
            raise ValidationError("Error deserialising string.") from error


class HashedField(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        if value is None:
            return ""
        return value

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return idam_hash(value)
        except ValueError as error:
            raise ValidationError("Error deserialising string.") from error
