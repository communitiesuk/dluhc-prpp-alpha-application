from src.ma import ma
from src.models.eligible_domain import DomainModel


class EligibleDomainSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = DomainModel
        dump_only = ("id",)
        load_instance = True
