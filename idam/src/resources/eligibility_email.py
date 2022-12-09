from flask import request
from flask_restful import Resource
from marshmallow import ValidationError
from src.schemas.eligible_email_schema import EligibleEmailSchema
from src.models.eligible_email import EmailModel
from src.common import app_logger
from src.security.security import api_key_admin_only, api_key_all


logger = app_logger.logging.getLogger(__name__)

email_schema = EligibleEmailSchema()


class EligibilityEmailResource(Resource):
    """Manages eligibility emails."""

    @classmethod
    @api_key_admin_only
    def post(cls):
        try:
            email = email_schema.load(request.get_json())
        except ValidationError as e:
            return e.messages, 400

        if EmailModel.find_by_email(email.email_address):
            return {"message": "Email address already exists."}, 400

        email.save_to_db()

        return {"message": "Email address saved to eligibility database."}, 201

    @classmethod
    @api_key_all
    def get(cls, email_address=None):
        if email_address:
            email = EmailModel.find_by_email(email_address)
            if not email:
                return {"message": f"{email_address} not found."}, 404

            return email_schema.dump(email), 200
        else:
            # email_address was not supplied.
            emails = EmailModel.find_all()

            if not emails:
                return {"message": "No emails found."}, 404

            return list(map(lambda x: email_schema.dump(x), emails)), 200

    @classmethod
    @api_key_admin_only
    def delete(cls, email_id):
        email = EmailModel.find_by_id(email_id)
        if not email:
            return {"message": "Email address not found."}, 404

        email.delete_from_db()
        return {"message": "Email address deleted."}, 200
