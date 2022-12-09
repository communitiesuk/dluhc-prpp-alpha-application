from src.ma import ma
from src.models.org_db import OrgDbModel


class OrgDbSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = OrgDbModel
        dump_only = ("id",)
        load_instance = True
