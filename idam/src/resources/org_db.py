import json

from flask import request
from flask_restful import Resource
from marshmallow import ValidationError
from src.common import app_logger
from src.schemas.org_db_schema import OrgDbModel, OrgDbSchema
from src.security.security import api_key_admin_only
import src.common.error_messages as error_messages

logger = app_logger.logging.getLogger(__name__)

org_schema = OrgDbSchema()

org_schema_search_output = OrgDbSchema(only=["id", "establishment_name"])

QUERY_FORMAT_ERROR = {
    "message": "query filter format not recognised see: https://flask-restless.readthedocs.io/en/stable/searchformat.html"
}, 400


class OrgResource(Resource):
    @classmethod
    @api_key_admin_only
    def post(cls):
        try:
            org_record = org_schema.load(request.get_json())
        except ValidationError as e:
            logger.debug(e)
            return {"message": f"{e}"}, 400

        try:
            org_record.save_to_db()
        except Exception as e:
            logger.debug(e)
            return {"message": error_messages.SERVER_ERROR_MESSAGE}, 500

        return {"message": "Record saved to database."}, 201

    @classmethod
    def get(cls, record_id=None):
        logger.debug(request.args)

        if record_id:
            record = OrgDbModel.find_by_id(record_id)
            return org_schema.dump(record), 200

        q = request.args.get("q", None)
        if not q:
            orgs = OrgDbModel.find_all()

            if not orgs:
                return {"message": "No org records found."}, 404

            return list(map(lambda x: org_schema.dump(x), orgs)), 200

        # Query format is as per https://flask-restless.readthedocs.io/en/stable/searchformat.html

        q = json.loads(q)

        if "filters" not in q.keys():
            return QUERY_FORMAT_ERROR

        try:
            for query in q["filters"]:
                logger.debug(query)
                if query["name"] == "establishment_name":
                    if query["op"] == "like":
                        criteria = query.get("val", "")
                        results = OrgDbModel.find_by_establishment_names_like(
                            f"%{criteria}%"
                        )
                        logger.debug(results)
                        return [org_schema_search_output.dump(x) for x in results], 200
        except Exception as e:
            logger.debug(e)
            return {"message": error_messages.SERVER_ERROR_MESSAGE}, 500

        return {"message": "Query not supported."}, 400

    @classmethod
    @api_key_admin_only
    def delete(cls, record_id):
        org_record = OrgDbModel.find_by_id(record_id)
        if not org_record:
            return {"message": "Record not found."}, 404

        org_record.delete_from_db()
        return {"message": "Record deleted."}, 200
