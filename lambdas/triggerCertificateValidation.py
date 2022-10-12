import json
import boto3
import uuid

textract = boto3.client('textract')
stepfunctions = boto3.client('stepfunctions')

STEP_FUNCTION_ARN = "arn:aws:states:eu-west-2:269164175472:stateMachine:HelloWorld"
S3_BUCKET_NAME = "dluhc-prpp-alpha-5472-certificate-testing"

s3_bucket = boto3.resource('s3').Bucket('dluhc-prpp-alpha-5472-certificate-testing')



def trigger_step_function(job_id=None, status=None, filename=None, bucket=None, job_tag=None):
    input = {'jobId': job_id, 'status': status, 'filename': filename, 'bucket': bucket, 'job_tag': job_tag}
    json_content = json.dumps(input)
    name = f"dluhc_confidence_analysis_{uuid.uuid4()}"
    print(f"Starting step function workflow for PDF confidence score with input: {input}")
    stepfunctions.start_execution(
        stateMachineArn=STEP_FUNCTION_ARN,
        name=name,
        input=json_content,
    )


def lambda_handler(event, context):
    print(event, context)
    for record in event['Records']:
        message = json.loads(record['Sns']['Message'])
        job_id = message['JobId']
        status = message['Status']
        job_tag = message["JobTag"]
        
        filename = message['DocumentLocation']['S3ObjectName']

        print(f'JobId {job_id} has finished with status {status} for file {filename}')

        # start fail certificate validation workflow
        if status != 'SUCCEEDED':
            response = trigger_step_function(job_id=job_id, status=status, filename=filename, bucket=S3_BUCKET_NAME, job_tag=job_tag)

        
        # start successful certificate validation workflow
        response = trigger_step_function(job_id=job_id, status=status, filename=filename, bucket=S3_BUCKET_NAME, job_tag=job_tag)

        return response