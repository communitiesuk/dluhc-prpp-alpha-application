import json
import boto3
import uuid
import sys
import re
from collections import defaultdict

textract = boto3.client('textract')
stepfunctions = boto3.client('stepfunctions')

s3_bucket = boto3.resource('s3').Bucket('dluhc-prpp-alpha-5472-certificate-testing')

STEP_FUNCTION_ARN = "arn:aws:states:eu-west-2:269164175472:stateMachine:HelloWorld"

S3_TEMP_FOLDER = "textract_temp"


def get_detected_text(job_id: str, keep_newlines: bool = True) -> str:
    """
    Giving job_id, return plain text extracted from input document.
    :param job_id: Textract DetectDocumentText job Id
    :param keep_newlines: if True, output will have same lines structure as the input document
    :return: plain text as extracted by Textract
    """
    max_results = 1000
    pagination_token = None
    finished = False
    text = ''

    while not finished:
        if pagination_token is None:
            response = textract.get_document_text_detection(JobId=job_id,
                                                                   MaxResults=max_results)
        else:
            response = textract.get_document_text_detection(JobId=job_id,
                                                                   MaxResults=max_results,
                                                                   NextToken=pagination_token)

        if 'NextToken' in response:
            pagination_token = response['NextToken']
        else:
            finished = True

    return response
    
    
def get_textract_analysis(job_id: str=None):
    """
    Giving job_id, return plain text extracted from input document.
    :param job_id: Textract DetectDocumentText job Id
    :param keep_newlines: if True, output will have same lines structure as the input document
    :return: plain text as extracted by Textract
    """
    max_results = 1000
    pagination_token = None
    finished = False
    text = ''

    while not finished:
        if pagination_token is None:
            response = textract.get_document_analysis(JobId=job_id,
                                                                   MaxResults=max_results)
        else:
            response = textract.get_document_analysis(JobId=job_id,
                                                                   MaxResults=max_results,
                                                                   NextToken=pagination_token)
        print("Response", response)
        if 'NextToken' in response:
            pagination_token = response['NextToken']
        else:
            finished = True

    return response
    
    
def get_detected_form(analysis_response=None):
    key_map, value_map, block_map = get_kv_map(analysis_response)
    # Get Key Value relationship
    kvs = get_kv_relationship(key_map, value_map, block_map)
    print("\n\n== FOUND KEY : VALUE pairs ===\n")
    # print_kvs(kvs)
    print(type(kvs))
    print(kvs)
    return kvs


def get_kv_map(analysis_response=None):
    # Get the text blocks
    blocks = analysis_response['Blocks']

    # get key and value maps
    key_map = {}
    value_map = {}
    block_map = {}
    for block in blocks:
        block_id = block['Id']
        block_map[block_id] = block
        if block['BlockType'] == "KEY_VALUE_SET":
            if 'KEY' in block['EntityTypes']:
                key_map[block_id] = block
            else:
                value_map[block_id] = block

    return key_map, value_map, block_map
    
    
def get_kv_relationship(key_map, value_map, block_map):
    kvs = defaultdict(list)
    for block_id, key_block in key_map.items():
        value_block = find_value_block(key_block, value_map)
        key = get_text(key_block, block_map)
        val = get_text(value_block, block_map)
        kvs[key].append(val)
    return kvs
    

def find_value_block(key_block, value_map):
    for relationship in key_block['Relationships']:
        if relationship['Type'] == 'VALUE':
            for value_id in relationship['Ids']:
                value_block = value_map[value_id]
    return value_block
    

def print_kvs(kvs):
    for key, value in kvs.items():
        print(key, ":", value)


############ 
    


def get_detected_table(analysis_response=None, file_name=None):
    blocks = analysis_response['Blocks']
    table_csv = get_table_csv_results(blocks)
    return table_csv
    
    
def get_table_csv_results(blocks):
    blocks_map = {}
    table_blocks = []
    for block in blocks:
        blocks_map[block['Id']] = block
        if block['BlockType'] == "TABLE":
            table_blocks.append(block)

    if len(table_blocks) <= 0:
        return "<b> NO Table FOUND </b>"

    csv = ''
    for index, table in enumerate(table_blocks):
        csv += generate_table_csv(table, blocks_map, index + 1)
        csv += '\n\n'
        # In order to generate separate CSV file for every table, uncomment code below
        #inner_csv = ''
        #inner_csv += generate_table_csv(table, blocks_map, index + 1)
        #inner_csv += '\n\n'
        #output_file = file_name + "___" + str(index) + ".csv"
        # replace content
        #with open(output_file, "at") as fout:
        #    fout.write(inner_csv)

    return csv
    
    
def generate_table_csv(table_result, blocks_map, table_index):
    rows = get_rows_columns_map(table_result, blocks_map)

    table_id = 'Table_' + str(table_index)

    # get cells.
    csv = 'Table: {0}\n\n'.format(table_id)

    for row_index, cols in rows.items():

        for col_index, text in cols.items():
            csv += '{}'.format(text) + ","
        csv += '\n'

    csv += '\n'
    return csv
    
    
def get_rows_columns_map(table_result, blocks_map):
    rows = {}
    for relationship in table_result['Relationships']:
        if relationship['Type'] == 'CHILD':
            for child_id in relationship['Ids']:
                try:
                    cell = blocks_map[child_id]
                    if cell['BlockType'] == 'CELL':
                        row_index = cell['RowIndex']
                        col_index = cell['ColumnIndex']
                        if row_index not in rows:
                            # create new row
                            rows[row_index] = {}

                        # get the text value
                        rows[row_index][col_index] = get_text(cell, blocks_map)
                except KeyError as e:
                    print("Error extracting Table data - {}:".format(KeyError))
                    print(e)
                    pass
    return rows
    
def get_text(result, blocks_map):
    text = ''
    if 'Relationships' in result:
        for relationship in result['Relationships']:
            if relationship['Type'] == 'CHILD':
                for child_id in relationship['Ids']:
                    try:
                        word = blocks_map[child_id]
                        if word['BlockType'] == 'WORD':
                            text += word['Text'] + ' '
                        if word['BlockType'] == 'SELECTION_ELEMENT':
                            if word['SelectionStatus'] == 'SELECTED':
                                text += 'X '
                    except KeyError as e:
                        print("Error extracting Table data - {}:".format(KeyError))
                        print(e)

    return text




def lambda_handler(event, context):
    print(event, context)
    
    job_id = event['jobId']
    job_tag = event["job_tag"]
    status = event['status']
    filename = event['filename']
    bucket = event["bucket"]

    # GET TEXTRACT ANALYSIS
    # text = get_detected_text(job_id) # TEXT EXTRACTION ONLY
    analysis = get_textract_analysis(job_id) # FORMS, TABLE, TEXT EXTRACTION
    
    # TEXT JSON EXPORT
    # to_json = {'Document': filename, 'ExtractedText': text, 'TextractJobId': job_id}
    to_json = {'Document': filename, 'ExtractedAnalysis': analysis, 'TextractJobId': job_id}
    json_content = json.dumps(to_json).encode('UTF-8')
    output_file_name = filename.split('/')[-1].rsplit('.', 1)[0] + '.json'
    document_type = filename.split('/')[1].rsplit('.', 1)[0]
    # response = s3_bucket.Object(f'textract_temp/{job_tag}/{output_file_name}').put(Body=bytes(json_content))
    response = s3_bucket.Object(f'textract_temp/{job_tag}/textract_output.json').put(Body=bytes(json_content))

    # FORMS EXPORT
    form = get_detected_form(analysis) # TO IMPLEMENT
    json_content = json.dumps(form).encode('UTF-8')
    response = s3_bucket.Object(f'textract_temp/{job_tag}/key_value_list.json').put(Body=(json_content))
    
    # TABLE CSV EXPORT
    tables = get_detected_table(analysis, filename) # TO IMPLEMENT
    response = s3_bucket.Object(f'textract_temp/{job_tag}/tables.csv').put(Body=(tables))
    
    print(f"JobId {job_id} has finished with status {status} for file {job_tag}")
    
    output_dict = {
        "job_id": job_id,
        "job_tag": job_tag,
        "bucket": bucket,
        "folder": S3_TEMP_FOLDER,
        "document_type": document_type,
        "json_text": "textract_output.json",
        "key_value_list": "key_value_list.json",
        "table": "tables.csv",
    }

    return output_dict
