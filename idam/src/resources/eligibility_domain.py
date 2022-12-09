from flask import request
from flask_restful import Resource
from marshmallow import ValidationError
from src.schemas.eligible_domain_schema import EligibleDomainSchema
from src.models.eligible_domain import DomainModel
from src.common import app_logger
from src.security.security import api_key_admin_only, api_key_all

logger = app_logger.logging.getLogger(__name__)

domain_schema = EligibleDomainSchema()


class EligibilityDomainResource(Resource):
    """Manages eligibility domains."""

    @classmethod
    @api_key_admin_only
    def post(cls):
        try:
            domain = domain_schema.load(request.get_json())
            logger.debug("domain={}".format(domain.domain_name))
        except ValidationError as e:
            return e.messages, 400

        if DomainModel.find_by_domain_name(domain.domain_name):
            return {"message": "Domain name already exists."}, 400

        domain.save_to_db()

        return {"message": "Domain name saved to eligibility database."}, 201

    @classmethod
    @api_key_all
    def get(cls, domain_name=None):
        if domain_name:
            domain = DomainModel.find_by_domain_name(domain_name)
            if not domain:
                return {"message": f"Domain {domain_name} not found."}, 404

            return domain_schema.dump(domain), 200
        else:
            # domain_name was not supplied.
            domains = DomainModel.find_all()

            if not domains:
                return {"message": "No domains found."}, 404

            return list(map(lambda x: domain_schema.dump(x), domains)), 200

    @classmethod
    @api_key_admin_only
    def delete(cls, domain_id):
        domain = DomainModel.find_by_id(domain_id)
        if not domain:
            return {"message": "Domain name not found."}, 404

        domain.delete_from_db()
        return {"message": "Domain name deleted."}, 200
