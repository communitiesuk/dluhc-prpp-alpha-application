import json
import boto3
import uuid
import sys
import re
from collections import defaultdict

textract = boto3.client('textract')
stepfunctions = boto3.client('stepfunctions')
s3 = boto3.client('s3')

s3_bucket = boto3.resource('s3').Bucket('dluhc-prpp-alpha-5472-certificate-testing')

def lambda_handler(event, context):
    print(event)
    document_type = None
    job_id = event[0].get('job_id')
    job_tag = event[0].get('job_tag')
    entities = event[0].get('entities')
    confidence = event[0].get('confidence')
    
    
    if event[0]['statusCode'] == 400:
        document_type = "check"
        return {
            'statusCode': 400,
            'job_id': job_id,
            'job_tag': job_tag,
            'document_type': document_type,
        } 
    
    if int(event[0]['confidence']['overall']) > 30:
        document_type = "gas"
    else:
        document_type = "check"
        
    response = s3_bucket.Object(f'output/{document_type}/{job_tag}/entities.json').put(Body=(json.dumps(entities)))
    response = s3_bucket.Object(f'output/{document_type}/{job_tag}/confidence.json').put(Body=(json.dumps(confidence)))
    
    return {
        'statusCode': 200,
        'job_id': job_id,
        'job_tag': job_tag,
        'document_type': document_type,
        'entities': f"output/gas/{job_tag}/entities.json",
        'confidence': f"output/gas/{job_tag}/confidence.json",
    }
