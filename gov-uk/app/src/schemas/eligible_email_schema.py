from src.ma import ma
from src.models.eligible_email import EmailModel


class EligibleEmailSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = EmailModel
        dump_only = ("id",)
        load_instance = True
