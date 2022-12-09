from marshmallow import Schema, fields, ValidationError
from app.src.common.utils import idam_encode, idam_decode


class HashedField(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        if value is None:
            return ""
        return idam_decode(value)

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return idam_encode(value)
        except ValueError as error:
            raise ValidationError("Error deserialising string.") from error


class AccessSchemaHashed(Schema):
    access_code = fields.Str()
    token_type = fields.Str()
    expiry = fields.Int()
    access_token = HashedField()
    refresh_token = HashedField()
    session_id = fields.Str()


class AccessSchema(Schema):
    access_code = fields.Str()
    token_type = fields.Str()
    expiry = fields.Int()
    access_token = fields.Str()
    refresh_token = fields.Str()
    session_id = fields.Str()
