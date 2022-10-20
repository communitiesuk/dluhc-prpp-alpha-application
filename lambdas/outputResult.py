import json
import boto3
import uuid
import sys
import re
from collections import defaultdict

textract = boto3.client("textract")
stepfunctions = boto3.client("stepfunctions")
s3 = boto3.client("s3")

s3_bucket = boto3.resource("s3").Bucket("dluhc-prpp-alpha-5472-certificate-testing")


def lambda_handler(event, context):
    print(event)
    job_id = event[0].get("job_id")
    job_tag = event[0].get("job_tag")
    document_type = event[0].get("document_type")
    features = event[0].get("features")
    postcodes = event[0].get("postcodes")
    addresses = event[0].get("addresses")
    feature_score = event[0].get("feature_score")
    address_score = event[0].get("address_score")
    dates = event[0].get("dates")
    valid_date = event[0].get("valid_date")
    valid_serial = event[0].get("valid_serial")
    rules = event[0].get("rules")

    if event[0]["statusCode"] == 400:
        document_type = "check"
        return {
            "statusCode": 400,
            "job_id": job_id,
            "job_tag": job_tag,
            "document_type": document_type,
        }

    # if int(event[0]['confidence']['overall']) > 30:
    #     document_type = "gas"
    # else:
    #     document_type = "check"

    response = s3_bucket.Object(f"output/{document_type}/{job_tag}/features.json").put(
        Body=(json.dumps(features))
    )
    response = s3_bucket.Object(
        f"output/{document_type}/{job_tag}/feature_score.json"
    ).put(Body=(json.dumps(feature_score)))
    response = s3_bucket.Object(
        f"output/{document_type}/{job_tag}/address_score.json"
    ).put(Body=(json.dumps(address_score)))

    return {
        "statusCode": 200,
        "job_id": job_id,
        "job_tag": job_tag,
        "document_type": document_type,
        "features": f"output/{document_type}/{job_tag}/feature_score.json",
        "address": f"output/{document_type}/{job_tag}/address_score.json",
    }
