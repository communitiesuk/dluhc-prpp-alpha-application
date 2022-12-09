from src.ma import ma
from src.models.blocked_emails import BlockedEmailModel


class BlockedEmailSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = BlockedEmailModel
        dump_only = ("id",)
        load_instance = True
