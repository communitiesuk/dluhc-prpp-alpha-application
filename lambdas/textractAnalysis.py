import json
import boto3
import io
import os
import logging
import urllib
import uuid
from urllib.parse import unquote_plus
from botocore.exceptions import ClientError

S3_BUCKET = "dluhc-prpp-alpha-5472-certificate-testing"
SNS_TOPIC_ARN = 'arn:aws:sns:eu-west-2:269164175472:textractNotify'
ROLE_ARN = "arn:aws:iam::269164175472:role/AWSTextractSNS"
VERSION = "a0.0.2"

print('Loading function')

logger = logging.getLogger(__name__)

# Amazon S3 Client
s3 = boto3.client('s3')

# Amazon Textract client
textract = boto3.client('textract')





def lambda_handler(event, context):
    print("Triggered getTextFromS3PDF event: ", event)

    # Get the object from the event and show its content type
    
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = unquote_plus(record['s3']['object']['key'])
        job_tag = str(uuid.uuid4())

        print(f'Document detection for {bucket}/{key}')

        try:
            textract.start_document_analysis(
                DocumentLocation= { 
                    "S3Object": { 
                        "Bucket": bucket, 
                        "Name": key
                        
                    }
                    
                },
                FeatureTypes=['TABLES','FORMS'],
                JobTag=job_tag,
                NotificationChannel={
                    'RoleArn': ROLE_ARN,
                    'SNSTopicArn': SNS_TOPIC_ARN
                    
                },
                OutputConfig={
                    'S3Bucket': bucket,
                    'S3Prefix': f"textract_temp/{job_tag}"
                    
                }
            )
            print('Triggered PDF Processing for ' + key)
        except Exception as e:
            print(f"Error with object: key: {key}, bucket: {bucket}, folder: {job_tag}, error: {e}")
            raise e 